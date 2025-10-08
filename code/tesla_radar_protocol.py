#!/usr/bin/env python3
"""
Tesla Radar Protocol Implementation
Based on the working Panda safety layer (safety_teslaradar.h)
Implements proper frequency-based message transmission and VIN protocol
"""

import os
import sys
import glob
import math
import csv
import json
from pathlib import Path
import can
import time
import struct
import threading
from collections import Counter, defaultdict
from typing import Optional

import cantools


_RADAR_DBC = None
_TESLA_CAN_DBC = None
_PLANT_FAILURE_MAP = None

_DEFAULT_175_SEQUENCE = [
    0x00,
    0x10,
    0x20,
    0x30,
    0x40,
    0x50,
    0x60,
    0x70,
    0x80,
    0x90,
    0xA0,
    0xB0,
    0xC0,
    0xD0,
    0xE0,
    0xF0,
]

_DEFAULT_1D8_SEQUENCE = [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0]

_DEFAULT_2C1_FALLBACK = {
    0x00: bytes.fromhex("00 00 00 00 00 00 00 00"),
    0x01: bytes.fromhex("01 00 00 00 00 00 64 00"),
    0x02: bytes.fromhex("02 0C 83 0C 00 7F 03 08"),
    0x03: bytes.fromhex("03 9C 40 16 00 80 57 00"),
    0x04: bytes.fromhex("04 80 80 00 00 00 40 08"),
    0x05: bytes.fromhex("05 00 00 00 00 00 00 00"),
    0x06: bytes.fromhex("06 00 00 00 40 00 00 00"),
    0x07: bytes.fromhex("07 00 00 00 00 00 00 00"),
    0x10: bytes.fromhex("10 4C 30 0E 8E 1F 00 00"),
    0x20: bytes.fromhex("20 8B 2C 0D 8D 1F 00 00"),
    0x30: bytes.fromhex("30 CC 30 0C 8B 1F 00 00"),
    0x40: bytes.fromhex("40 0B 2D 0C 8A 1F 00 00"),
    0x50: bytes.fromhex("50 4A 29 09 89 1F 00 00"),
    0x60: bytes.fromhex("60 89 25 09 89 19 00 00"),
    0x70: bytes.fromhex("70 CB 2D 0D 8D 1F 00 00"),
    0xC0: bytes.fromhex("C0 0B 2F 0E 8D 1F 00 00"),
}


def _load_radar_dbc():
    global _RADAR_DBC
    if _RADAR_DBC is None:
        dbc_path = os.path.join(os.path.dirname(__file__), "tesla_radar.dbc")
        with open(dbc_path, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.read()
        sanitized_lines = []
        for line in raw.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("VAL_ "):
                continue
            sanitized_lines.append(line)
        sanitized = "\n".join(sanitized_lines)
        _RADAR_DBC = cantools.database.load_string(sanitized)
    return _RADAR_DBC


def _load_tesla_can_dbc():
    global _TESLA_CAN_DBC
    if _TESLA_CAN_DBC is not None:
        return _TESLA_CAN_DBC

    dbc_path = os.path.join(os.path.dirname(__file__), "tesla_can.dbc")
    if not os.path.exists(dbc_path):
        return None

    sanitized_lines = []
    with open(dbc_path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            stripped = line.lstrip()
            if stripped.startswith("VAL_ "):
                continue
            if "IBST_" in line or ">>!<<" in line:
                continue
            sanitized_lines.append(line.rstrip("\n"))

    sanitized = "\n".join(sanitized_lines)
    try:
        _TESLA_CAN_DBC = cantools.database.load_string(sanitized)
    except Exception as exc:
        print(f"⚠️  Failed to load tesla_can.dbc: {exc}")
        _TESLA_CAN_DBC = None
    return _TESLA_CAN_DBC


def setup_can(interface="can1", bitrate=500000):
    """Setup CAN interface with platform-specific handling."""
    if sys.platform.startswith("darwin"):
        channel = os.environ.get("TESLA_RADAR_SERIAL", interface)

        if not channel.startswith("/dev/"):
            candidates = sorted(glob.glob("/dev/cu.usbmodem*"))
            candidates.extend(sorted(glob.glob("/dev/cu.usbserial*")))
            if not candidates:
                raise RuntimeError(
                    "No SLcan-compatible serial devices found. Set TESLA_RADAR_SERIAL to the device path."  # noqa: E501
                )
            channel = candidates[0]

        print(f"Opening SLcan interface {channel} at {bitrate}bps")
        return can.Bus(
            interface="slcan",
            channel=channel,
            bitrate=bitrate,
            receive_own_messages=False,
        )

    os.system(f"sudo ip link set {interface} down")
    os.system(
        f"sudo ip link set {interface} up type can bitrate {bitrate} restart-ms 100"
    )
    os.system(f"sudo ifconfig {interface} txqueuelen 1000")
    print(f"{interface} up at {bitrate}bps")
    return can.interface.Bus(channel=interface, interface="socketcan")


class TeslaRadarProtocol:
    """Complete Tesla Radar Protocol Implementation"""

    def __init__(
        self,
        can_bus,
        vin="5YJSB7E43GF113105",
        debug=False,
        *,
        performance_config=2,
        air_suspension=3,
        chassis_type=1,
        four_wheel_drive=None,
        autopilot_level=3,
    ):
        self.can_bus = can_bus
        self.debug = debug
        self.running = False

        # Radar state (matches Panda safety layer)
        self.tesla_radar_status = 0  # 0-not present, 1-initializing, 2-active
        self.tesla_radar_vin_complete = 0  # set to 7 when complete
        self.tesla_radar_should_send = 1  # always send
        self.tesla_radar_counter = 0
        self.init_message_count = 0
        self.status_message_count = 0
        self.last_init_data = None
        self.last_status_data = None
        self.error_code_counts = Counter()
        self.last_system_status_data = None
        self.error_code_payloads = defaultdict(set)
        self.plant_failure_map = _load_plant_failure_map()
        self.dbc = _load_radar_dbc()
        self.dbc_msg169 = self.dbc.get_message_by_frame_id(0x169)
        self.simulation_start_ts = time.time()

        # Configuration
        self.radarPosition = (
            0  # 0=Model S pre-facelift, 1=Model S post-facelift, 2=Model X
        )
        self.radarEpasType = 0  # 0=Bosch L538, 1=Bosch L405
        self.actual_speed_kph = 0.0  # Simulated vehicle speed
        self.base_speed_kph = 0.0
        # Default AWD to VIN heuristic unless explicitly overridden
        if four_wheel_drive is None:
            self.force_awd = True
        else:
            self.force_awd = bool(four_wheel_drive)
        self.dynamic_phase = 0.0
        self.tesla_can_dbc = _load_tesla_can_dbc()
        self.msg_101 = self.msg_214 = None
        self.msg_108 = self.msg_118 = self.msg_145 = None
        self.msg_20A = self.msg_00E = self.msg_045 = self.msg_398 = None
        if self.tesla_can_dbc is not None:
            try:
                self.msg_101 = self.tesla_can_dbc.get_message_by_frame_id(0x101)
                for signal in self.msg_101.signals:
                    if signal.name == "GTW_epasPowerMode":
                        signal.minimum = None
                        signal.maximum = None
            except KeyError:
                pass
            try:
                self.msg_214 = self.tesla_can_dbc.get_message_by_frame_id(0x214)
                for signal in self.msg_214.signals:
                    if signal.name == "EPB_epasEACAllow":
                        signal.minimum = None
                        signal.maximum = None
            except KeyError:
                pass
            try:
                self.msg_108 = self.tesla_can_dbc.get_message_by_frame_id(0x108)
            except KeyError:
                pass
            try:
                self.msg_118 = self.tesla_can_dbc.get_message_by_frame_id(0x118)
            except KeyError:
                pass
            try:
                self.msg_145 = self.tesla_can_dbc.get_message_by_frame_id(0x145)
            except KeyError:
                pass
            try:
                self.msg_20A = self.tesla_can_dbc.get_message_by_frame_id(0x20A)
            except KeyError:
                pass
            try:
                self.msg_00E = self.tesla_can_dbc.get_message_by_frame_id(0x00E)
            except KeyError:
                pass
            try:
                self.msg_045 = self.tesla_can_dbc.get_message_by_frame_id(0x045)
            except KeyError:
                pass
            try:
                self.msg_398 = self.tesla_can_dbc.get_message_by_frame_id(0x398)
            except KeyError:
                pass

        self.epas_control_counter = 0
        self.epb_control_counter = 1

        # Optional SydneyG-derived reference sequences for missing IDs
        self.reference_sequences = self._load_reference_sequences(
            target_ids=[0x132, 0x13D, 0x175, 0x186, 0x1D8, 0x257, 0x2C1],
            limit_per_id=1024,
        )
        self.reference_indexes = {msg_id: 0 for msg_id in self.reference_sequences}

        # VIN (17 characters, padded with spaces)
        self.radar_VIN = (vin + " " * 17)[:17]
        if four_wheel_drive is None:
            if len(self.radar_VIN) >= 8 and self.radar_VIN[7] in {"2", "3", "4", "P", "D"}:
                self.force_awd = True

        # Gateway configuration (overridable via CLI)
        self.gateway_performance_config = performance_config
        self.gateway_air_suspension = air_suspension
        self.gateway_chassis_type = chassis_type
        self.gateway_autopilot_level = autopilot_level
        self.gateway_epas_type = self.radarEpasType
        self.gateway_country = 826  # default UK (matches VIN)
        self.gateway_rhd = 1
        self.gateway_das_hw = 2
        self.gateway_park_assist = 1
        self.gateway_forward_radar_hw = 1
        self.gateway_front_corner_radar_hw = 0
        self.gateway_rear_corner_radar_hw = 0
        self.gateway_body_controls_type = 1
        self.gateway_park_sensor_geometry = 1
        self.gateway_wheel_type = 4
        self.gateway_brake_hw_type = 2
        self.gateway_folding_mirrors = 1
        self.gateway_eu_vehicle = 1
        self.gateway_unknown1 = 0
        self.gateway_unknown2 = 0
        self.gateway_unknown3 = 0
        self.gateway_rear_seat_controller_mask = 0
        self.gateway_raw_398_payload: Optional[bytes] = None

        # Message counters (exactly like Panda)
        self.tesla_radar_x2B9_id = 0
        self.tesla_radar_x159_id = 0
        self.tesla_radar_x219_id = 0
        self.tesla_radar_x149_id = 0
        self.tesla_radar_x129_id = 0
        self.tesla_radar_x1A9_id = 0
        self.tesla_radar_x199_id = 0
        self.tesla_radar_x169_id = 0
        self.tesla_radar_x119_id = 0
        self.tesla_radar_x109_id = 0

        # CRC lookup table (from Panda)
        self.crc_lookup = [
            0x00,
            0x1D,
            0x3A,
            0x27,
            0x74,
            0x69,
            0x4E,
            0x53,
            0xE8,
            0xF5,
            0xD2,
            0xCF,
            0x9C,
            0x81,
            0xA6,
            0xBB,
            0xCD,
            0xD0,
            0xF7,
            0xEA,
            0xB9,
            0xA4,
            0x83,
            0x9E,
            0x25,
            0x38,
            0x1F,
            0x02,
            0x51,
            0x4C,
            0x6B,
            0x76,
            0x87,
            0x9A,
            0xBD,
            0xA0,
            0xF3,
            0xEE,
            0xC9,
            0xD4,
            0x6F,
            0x72,
            0x55,
            0x48,
            0x1B,
            0x06,
            0x21,
            0x3C,
            0x4A,
            0x57,
            0x70,
            0x6D,
            0x3E,
            0x23,
            0x04,
            0x19,
            0xA2,
            0xBF,
            0x98,
            0x85,
            0xD6,
            0xCB,
            0xEC,
            0xF1,
            0x13,
            0x0E,
            0x29,
            0x34,
            0x67,
            0x7A,
            0x5D,
            0x40,
            0xFB,
            0xE6,
            0xC1,
            0xDC,
            0x8F,
            0x92,
            0xB5,
            0xA8,
            0xDE,
            0xC3,
            0xE4,
            0xF9,
            0xAA,
            0xB7,
            0x90,
            0x8D,
            0x36,
            0x2B,
            0x0C,
            0x11,
            0x42,
            0x5F,
            0x78,
            0x65,
            0x94,
            0x89,
            0xAE,
            0xB3,
            0xE0,
            0xFD,
            0xDA,
            0xC7,
            0x7C,
            0x61,
            0x46,
            0x5B,
            0x08,
            0x15,
            0x32,
            0x2F,
            0x59,
            0x44,
            0x63,
            0x7E,
            0x2D,
            0x30,
            0x17,
            0x0A,
            0xB1,
            0xAC,
            0x8B,
            0x96,
            0xC5,
            0xD8,
            0xFF,
            0xE2,
            0x26,
            0x3B,
            0x1C,
            0x01,
            0x52,
            0x4F,
            0x68,
            0x75,
            0xCE,
            0xD3,
            0xF4,
            0xE9,
            0xBA,
            0xA7,
            0x80,
            0x9D,
            0xEB,
            0xF6,
            0xD1,
            0xCC,
            0x9F,
            0x82,
            0xA5,
            0xB8,
            0x03,
            0x1E,
            0x39,
            0x24,
            0x77,
            0x6A,
            0x4D,
            0x50,
            0xA1,
            0xBC,
            0x9B,
            0x86,
            0xD5,
            0xC8,
            0xEF,
            0xF2,
            0x49,
            0x54,
            0x73,
            0x6E,
            0x3D,
            0x20,
            0x07,
            0x1A,
            0x6C,
            0x71,
            0x56,
            0x4B,
            0x18,
            0x05,
            0x22,
            0x3F,
            0x84,
            0x99,
            0xBE,
            0xA3,
            0xF0,
            0xED,
            0xCA,
            0xD7,
            0x35,
            0x28,
            0x0F,
            0x12,
            0x41,
            0x5C,
            0x7B,
            0x66,
            0xDD,
            0xC0,
            0xE7,
            0xFA,
            0xA9,
            0xB4,
            0x93,
            0x8E,
            0xF8,
            0xE5,
            0xC2,
            0xDF,
            0x8C,
            0x91,
            0xB6,
            0xAB,
            0x10,
            0x0D,
            0x2A,
            0x37,
            0x64,
            0x79,
            0x5E,
            0x43,
            0xB2,
            0xAF,
            0x88,
            0x95,
            0xC6,
            0xDB,
            0xFC,
            0xE1,
            0x5A,
            0x47,
            0x60,
            0x7D,
            0x2E,
            0x33,
            0x14,
            0x09,
            0x7F,
            0x62,
            0x45,
            0x58,
            0x0B,
            0x16,
            0x31,
            0x2C,
            0x97,
            0x8A,
            0xAD,
            0xB0,
            0xE3,
            0xFE,
            0xD9,
            0xC4,
        ]

        # State tracking
        self.last_radar_signal = 0
        self.start_time = time.time()
        self.last_state_update_ts = self.start_time
        self.last_speed_kph = 0.0
        self.vehicle_accel = 0.0
        self.brake_active = False
        self.accel_active = False
        self.gear_state = 0x04
        self.turn_indicator = 0
        self.steering_angle_deg = 0.0
        self.steering_rate_dps = 0.0
        self.steering_torque_nm = 0.0
        self.di_torque1_counter = 0
        self.di_torque2_counter = 0
        self.esp145_counter = 0
        self.stw_angle_counter = 0
        self.stw_actn_counter = 0

        # Fallback synthetic sequences when reference recordings aren't available
        self.synthetic_175_sequence = list(_DEFAULT_175_SEQUENCE)
        self.synthetic_175_index = 0
        self.synthetic_1d8_sequence = list(_DEFAULT_1D8_SEQUENCE)
        self.synthetic_1d8_index = 0
        self.synthetic_2c1_frames = dict(_DEFAULT_2C1_FALLBACK)
        self.synthetic_2c1_keys = sorted(self.synthetic_2c1_frames.keys())
        self.synthetic_2c1_index = 0

    def _load_reference_sequences(self, target_ids, limit_per_id=2048):
        sequences = {}
        targets = set(target_ids)

        base_dir = os.path.dirname(__file__)
        csv_candidates = []

        # Primary known dataset from SydneyG capture
        known_dir = os.path.join(base_dir, "2021.4.3_V0P3C6_fromWake_NoVin")
        known_csv = os.path.join(known_dir, "2021.4.3_V0P3C6_fromWake_NoVin.csv")
        if os.path.exists(known_csv):
            csv_candidates.append(known_csv)
        else:
            csv_candidates.extend(
                glob.glob(
                    os.path.join(
                        base_dir,
                        "2021.*fromWake*",
                        "*.csv",
                    )
                )
            )

        if not csv_candidates:
            # fallback to repository references (e.g., AP1 stop-and-go capture)
            ref_path = os.path.join(
                os.path.dirname(base_dir),
                "references",
                "TMS_2016_LOGS",
                "drive6_stopanggo_clean.csv",
            )
            if os.path.exists(ref_path):
                csv_candidates.append(ref_path)

        if not csv_candidates:
            return sequences

        csv_path = csv_candidates[0]
        try:
            with open(csv_path, newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    try:
                        msg_id = int(row["ID"], 16)
                    except (ValueError, KeyError):
                        continue

                    if msg_id not in targets:
                        continue

                    bucket = sequences.setdefault(msg_id, [])
                    if len(bucket) >= limit_per_id:
                        continue

                    try:
                        length = int(row.get("LEN", "8"))
                    except ValueError:
                        length = 8

                    data_bytes = []
                    for idx in range(1, min(length, 8) + 1):
                        key = f"D{idx}"
                        byte_str = row.get(key, "").strip()
                        if not byte_str:
                            break
                        if len(byte_str) != 2 or any(
                            ch not in "0123456789abcdefABCDEF" for ch in byte_str
                        ):
                            data_bytes = []
                            break
                        try:
                            data_bytes.append(int(byte_str, 16))
                        except ValueError:
                            data_bytes = []
                            break

                    if not data_bytes:
                        continue

                    bucket.append(bytes(data_bytes))
        except FileNotFoundError:
            return {}
        except Exception as exc:
            if self.debug:
                print(f"⚠️  Failed to load reference sequences from {csv_path}: {exc}")
            return {}

        return {k: v for k, v in sequences.items() if v}

    def _update_vehicle_state(self):
        now = time.time()
        elapsed = now - self.simulation_start_ts
        cycle = 60.0
        phase = (elapsed % cycle) / cycle

        if phase < 0.2:  # accelerate to 100 km/h
            target_speed = 100.0 * (phase / 0.2)
            self.accel_active = True
            self.brake_active = False
        elif phase < 0.4:  # cruise
            target_speed = 100.0
            self.accel_active = False
            self.brake_active = False
        elif phase < 0.6:  # gentle brake to 30 km/h
            target_speed = 100.0 - 70.0 * ((phase - 0.4) / 0.2)
            self.accel_active = False
            self.brake_active = True
        elif phase < 0.8:  # accelerate again to 120
            target_speed = 30.0 + 90.0 * ((phase - 0.6) / 0.2)
            self.accel_active = True
            self.brake_active = False
        else:  # coast down to stop and shift to park
            target_speed = max(0.0, 120.0 * (1.0 - (phase - 0.8) / 0.2))
            self.accel_active = False
            self.brake_active = True

        dt = max(0.01, now - self.last_state_update_ts)
        self.vehicle_accel = (target_speed - self.last_speed_kph) / dt
        self.actual_speed_kph = target_speed
        self.last_speed_kph = target_speed
        self.last_state_update_ts = now

        # simple gear state logic: drive when moving, park when stopped
        if self.actual_speed_kph < 1.0 and phase >= 0.85:
            self.gear_state = 0x01  # park
        elif self.actual_speed_kph < 1.0 and phase < 0.25:
            self.gear_state = 0x02  # reverse early in cycle
        else:
            self.gear_state = 0x04  # drive

        # attitude indicators for turn signals
        if 0.45 < phase < 0.5:
            self.turn_indicator = 1  # left
        elif 0.7 < phase < 0.75:
            self.turn_indicator = 2  # right
        else:
            self.turn_indicator = 0

    def _send_reference_message(self, msg_id):
        seqs = self.reference_sequences.get(msg_id)
        if not seqs:
            return False

        idx = self.reference_indexes.get(msg_id, 0)
        payload = seqs[idx]
        if seqs:
            self.reference_indexes[msg_id] = (idx + 1) % len(seqs)

        if len(payload) < 8:
            payload = payload + bytes(8 - len(payload))

        try:
            self.can_bus.send(
                can.Message(
                    arbitration_id=msg_id,
                    data=payload,
                    is_extended_id=False,
                )
            )
            return True
        except Exception as exc:
            if self.debug:
                print(f"Send error for 0x{msg_id:03X}: {exc}")
            return False

    def add_tesla_crc(self, MLB, MHB, msg_len):
        """Calculate CRC8 using 1D poly, FF start, FF end (exactly like Panda)"""
        crc = 0xFF
        for x in range(msg_len):
            if x <= 3:
                v = (MLB >> (x * 8)) & 0xFF
            else:
                v = (MHB >> ((x - 4) * 8)) & 0xFF
            crc = self.crc_lookup[crc ^ v]
        return crc ^ 0xFF

    def add_tesla_cksm(self, data_low, data_high, msg_id, msg_len):
        """Calculate checksum (exactly like Panda)"""
        cksm = (0xFF & msg_id) + (0xFF & (msg_id >> 8))
        for x in range(msg_len):
            if x <= 3:
                v = (data_low >> (x * 8)) & 0xFF
            else:
                v = (data_high >> ((x - 4) * 8)) & 0xFF
            cksm = (cksm + v) & 0xFF
        return cksm

    def radar_VIN_char(self, pos, shift):
        """Get VIN character at position with shift (exactly like Panda)"""
        if pos < len(self.radar_VIN):
            return ord(self.radar_VIN[pos]) << (shift * 8)
        return 0

    def send_message(self, msg_id, data_low, data_high, msg_len):
        """Send CAN message"""
        # Pack data into 8 bytes
        data = bytearray(8)
        for i in range(4):
            data[i] = (data_low >> (i * 8)) & 0xFF
        for i in range(4):
            data[i + 4] = (data_high >> (i * 8)) & 0xFF

        # Truncate to actual message length
        data = data[:msg_len]

        # Pad to 8 bytes for CAN
        while len(data) < 8:
            data.append(0)

        msg = can.Message(arbitration_id=msg_id, data=data, is_extended_id=False)

        try:
            self.can_bus.send(msg)
            if self.debug:
                print(f"TX: 0x{msg_id:03X} = {data[:msg_len].hex()}")
        except Exception as e:
            print(f"Send error: {e}")

    def activate_tesla_radar(self):
        """Main radar activation function (exactly like Panda)"""
        # Only skip when protocol is paused
        if self.tesla_radar_should_send == 0:
            return

        # Send all messages at 100Hz
        self.send_199_message()
        self.send_169_message()
        self.send_119_message()
        self.send_109_message()
        self.send_118_message()
        self.send_108_message()
        self.send_00E_message()
        self.send_145_message()
        self.send_20A_message()
        self.send_045_message()
        self.send_132_message()
        self.send_13D_message()
        self.send_175_message()
        self.send_186_message()
        self.send_1D8_message()
        self.send_257_message()
        self.send_2C1_message()
        self.send_101_message()
        self.send_214_message()

        # Send all messages at 50Hz
        if self.tesla_radar_counter % 2 == 0:
            self.send_159_message()
            self.send_149_message()
            self.send_129_message()
            self.send_1A9_message()

        # Send all messages at 10Hz
        if self.tesla_radar_counter % 10 == 0:
            self.send_209_message()
            self.send_219_message()
            self.send_17C_message()
            self.send_398_message()

        # Send all messages at 4Hz
        if self.tesla_radar_counter % 25 == 0:
            self.send_2B9_message()
            self.send_508_messages()

        # Send all messages at 1Hz
        if self.tesla_radar_counter == 0:
            self.send_2A9_message()
            self.send_2D9_message()

        self.tesla_radar_counter += 1
        self.tesla_radar_counter = self.tesla_radar_counter % 100

    def send_199_message(self):
        """Send 0x199 message (exactly like Panda)"""
        MLB = 0x00207D2F
        MHB = 0x0000FF04 + (self.tesla_radar_x199_id << 20)
        crc = self.add_tesla_crc(MLB, MHB, 7)
        MHB = MHB + (crc << 24)
        self.tesla_radar_x199_id = (self.tesla_radar_x199_id + 1) % 16
        self.send_message(0x199, MLB, MHB, 8)

    def send_169_message(self):
        """Send 0x169 message with dynamic wheel speeds."""
        if self.dbc_msg169 is not None:
            speeds = self._generate_wheel_speeds()
            signals = {
                "ESP_wheelSpeedFrL_HS": speeds[0],
                "ESP_wheelSpeedFrR_HS": speeds[1],
                "ESP_wheelSpeedReL_HS": speeds[2],
                "ESP_wheelSpeedReR_HS": speeds[3],
                "Msg169Counter": self.tesla_radar_x169_id,
                "Msg169Checksum": 0,
            }
            payload = bytearray(self.dbc_msg169.encode(signals))
            checksum = (sum(payload[:-1]) + 0x76) & 0xFF
            payload[-1] = checksum
            self.tesla_radar_x169_id = (self.tesla_radar_x169_id + 1) % 16
            data_low = int.from_bytes(payload[:4], "little")
            data_high = int.from_bytes(payload[4:], "little")
            self.send_message(0x169, data_low, data_high, len(payload))
            self.actual_speed_kph = sum(speeds) / len(speeds)
            return

        # Fallback to legacy fixed-frame encoding
        speed_kph = int(self.actual_speed_kph / 0.04) & 0x1FFF
        MLB = (speed_kph | (speed_kph << 13) | (speed_kph << 26)) & 0xFFFFFFFF
        MHB = (
            (speed_kph >> 6) | (speed_kph << 7) | (self.tesla_radar_x169_id << 20)
        ) & 0x00FFFFFF
        cksm = self.add_tesla_cksm(MLB, MHB, 0x76, 7)
        MHB = MHB + (cksm << 24)
        self.tesla_radar_x169_id = (self.tesla_radar_x169_id + 1) % 16
        self.send_message(0x169, MLB, MHB, 8)

    def send_119_message(self):
        """Send 0x119 message (exactly like Panda)"""
        MLB = 0x11F41FFF
        MHB = 0x00000080 + self.tesla_radar_x119_id
        cksm = self.add_tesla_cksm(MLB, MHB, 0x17, 5)
        MHB = MHB + (cksm << 8)
        self.tesla_radar_x119_id = (self.tesla_radar_x119_id + 1) % 16
        self.send_message(0x119, MLB, MHB, 6)

    def send_109_message(self):
        """Send 0x109 message (exactly like Panda)"""
        MLB = 0x80000000 + (self.tesla_radar_x109_id << 13)
        MHB = 0x00
        cksm = self.add_tesla_cksm(MLB, MHB, 0x7, 7)
        MHB = MHB + (cksm << 24)
        self.tesla_radar_x109_id = (self.tesla_radar_x109_id + 1) % 8
        self.send_message(0x109, MLB, MHB, 8)

    def send_118_message(self):
        if self.msg_118 is None:
            return

        self.di_torque2_counter = (self.di_torque2_counter + 1) % 16
        gear = {0x01: 1, 0x02: 2, 0x04: 4}.get(self.gear_state, 4)
        vehicle_speed_raw = int(round((max(0.0, self.actual_speed_kph) + 25.0) / 0.05))
        torque_estimate = max(-100.0, min(100.0, self.vehicle_accel * 20.0))
        signals = {
            "DI_torqueEstimate": torque_estimate,
            "DI_gear": gear,
            "DI_brakePedal": 1 if self.brake_active else 0,
            "DI_vehicleSpeed": max(-25.0, min(179.75, self.actual_speed_kph)),
            "DI_gearRequest": gear,
            "DI_torqueInterfaceFailure": 0,
            "DI_torque2Counter": self.di_torque2_counter,
            "DI_brakePedalState": 3 if self.brake_active else 0,
            "DI_epbParkRequest": 1 if self.gear_state == 0x01 else 0,
            "DI_epbInterfaceReady": 1,
            "DI_torque2Checksum": 0,
        }

        payload = bytearray(self.msg_118.encode(signals))
        payload[-1] = 0
        mlb = int.from_bytes(payload[:4], "little")
        mhb = int.from_bytes(payload[4:], "little")
        checksum = self.add_tesla_cksm(mlb, mhb, 0x118, 5)
        payload[-1] = checksum & 0xFF
        self.can_bus.send(can.Message(arbitration_id=0x118, data=payload, is_extended_id=False))

    def send_108_message(self):
        if self.msg_108 is None:
            return

        self.di_torque1_counter = (self.di_torque1_counter + 1) % 8
        torque_driver = max(-60.0, min(60.0, self.steering_torque_nm))
        torque_motor = max(-120.0, min(120.0, self.vehicle_accel * 40.0))
        motor_rpm = max(0.0, min(10000.0, self.actual_speed_kph * 40.0))
        pedal_pos = 60.0 if self.accel_active else (10.0 if self.actual_speed_kph > 2 else 0.0)
        signals = {
            "DI_torqueDriver": torque_driver,
            "DI_torque1Counter": self.di_torque1_counter,
            "DI_torqueMotor": torque_motor,
            "DI_soptState": 0,
            "DI_motorRPM": motor_rpm,
            "DI_pedalPos": pedal_pos,
            "DI_torque1Checksum": 0,
        }

        payload = bytearray(self.msg_108.encode(signals))
        payload[-1] = 0
        mlb = int.from_bytes(payload[:4], "little")
        mhb = int.from_bytes(payload[4:], "little")
        checksum = self.add_tesla_cksm(mlb, mhb, 0x108, 7)
        payload[-1] = checksum & 0xFF
        self.can_bus.send(can.Message(arbitration_id=0x108, data=payload, is_extended_id=False))

    def send_145_message(self):
        if self.msg_145 is None:
            return

        self.esp145_counter = (self.esp145_counter + 1) % 16
        lon_accel = max(-7.0, min(7.0, self.vehicle_accel))
        lat_accel = max(-4.0, min(4.0, self.steering_angle_deg / 10.0))
        brake_press = 60.0 if self.brake_active else 5.0
        signals = {
            "ESP_longitudinalAccel": lon_accel,
            "ESP_stabilityControlSts2": 0,
            "ESP_brakeMasterCylPressQF": 1,
            "ESP_absBrakeEvent2": 0,
            "ESP_lateralAccel": lat_accel,
            "ESP_btcTargetState": 0,
            "ESP_ptcTargetState": 0,
            "ESP_vehicleStandstillSts": 1 if self.actual_speed_kph < 0.5 else 0,
            "ESP_brakeMasterCylPress": brake_press,
            "ESP_wheelSpeedsQF": 1,
            "ESP_espModeActive": 1,
            "ESP_lateralAccelQF": 1,
            "ESP_longitudinalAccelQF": 1,
            "ESP_145hCounter": self.esp145_counter,
            "ESP_145hChecksum": 0,
        }

        payload = bytearray(self.msg_145.encode(signals))
        payload[-1] = 0
        mlb = int.from_bytes(payload[:4], "little")
        mhb = int.from_bytes(payload[4:], "little")
        checksum = self.add_tesla_cksm(mlb, mhb, 0x145, 7)
        payload[-1] = checksum & 0xFF
        self.can_bus.send(can.Message(arbitration_id=0x145, data=payload, is_extended_id=False))

    def send_20A_message(self):
        if self.msg_20A is None:
            return

        status = 2 if self.brake_active else 1
        payload = bytearray(self.msg_20A.encode({"driverBrakeStatus": status}))
        self.can_bus.send(can.Message(arbitration_id=0x20A, data=payload, is_extended_id=False))

    def send_00E_message(self):
        if self.msg_00E is None:
            return

        self.stw_angle_counter = (self.stw_angle_counter + 1) % 16
        signals = {
            "StW_AnglHP": self.steering_angle_deg,
            "StW_AnglHP_Spd": self.steering_rate_dps,
            "StW_AnglHP_Sens_Id": 0,
            "StW_AnglHP_Sens_Stat": 0,
            "MC_STW_ANGLHP_STAT": self.stw_angle_counter,
            "CRC_STW_ANGLHP_STAT": 0,
        }
        payload = bytearray(self.msg_00E.encode(signals))
        payload[-1] = 0
        mlb = int.from_bytes(payload[:4], "little")
        mhb = int.from_bytes(payload[4:], "little")
        crc = self.add_tesla_crc(mlb, mhb, 7)
        payload[-1] = crc & 0xFF
        self.can_bus.send(can.Message(arbitration_id=0x00E, data=payload, is_extended_id=False))

    def send_045_message(self):
        if self.msg_045 is None:
            return

        self.stw_actn_counter = (self.stw_actn_counter + 1) % 16
        signals = {
            "SpdCtrlLvr_Stat": 0,
            "VSL_Enbl_Rq": 0,
            "SpdCtrlLvrStat_Inv": 0,
            "DTR_Dist_Rq": 100,  # mid-range following distance request
            "TurnIndLvr_Stat": self.turn_indicator,
            "HiBmLvr_Stat": 0,
            "WprWashSw_Psd": 0,
            "WprWash_R_Sw_Posn_V2": 0,
            "StW_Lvr_Stat": 0,
            "StW_Cond_Flt": 0,
            "StW_Cond_Psd": 0,
            "HrnSw_Psd": 0,
            "WprSw6Posn": 0,
            "MC_STW_ACTN_RQ": self.stw_actn_counter,
            "CRC_STW_ACTN_RQ": 0,
        }

        # Populate the individual steering switch plausibility bits (modelled as untouched).
        for idx in range(16):
            signals[f"StW_Sw{idx:02d}_Psd"] = 0
        payload = bytearray(self.msg_045.encode(signals))
        payload[-1] = 0
        mlb = int.from_bytes(payload[:4], "little")
        mhb = int.from_bytes(payload[4:], "little")
        crc = self.add_tesla_crc(mlb, mhb, 7)
        payload[-1] = crc & 0xFF
        self.can_bus.send(can.Message(arbitration_id=0x045, data=payload, is_extended_id=False))

    def send_132_message(self):
        if self._send_reference_message(0x132):
            return

        speed_byte = int(max(0.0, min(255.0, self.actual_speed_kph * 2.0)))
        torque_scaled = int(max(0.0, min(255.0, abs(self.steering_torque_nm) * 4.0)))
        angle_scaled = int(max(0.0, min(61.0, abs(self.steering_angle_deg))))
        payload = bytearray(8)
        payload[0] = speed_byte
        payload[1] = 0x8C | (self.di_torque1_counter & 0x01)
        payload[2] = torque_scaled
        payload[3] = 0x80 if self.accel_active else 0x00
        payload[4] = angle_scaled
        payload[5] = 0x80 if self.brake_active else 0x40
        payload[6] = 0xFF
        payload[7] = 0x0F
        self.can_bus.send(can.Message(arbitration_id=0x132, data=payload, is_extended_id=False))

    def send_13D_message(self):
        if self._send_reference_message(0x13D):
            return

        payload = bytearray(8)
        payload[0] = 1 if self.accel_active else 0
        payload[4] = max(0x20, min(0xFF, int(self.actual_speed_kph * 2.0)))
        self.can_bus.send(can.Message(arbitration_id=0x13D, data=payload, is_extended_id=False))

    def send_175_message(self):
        if self._send_reference_message(0x175):
            return

        if not self.synthetic_175_sequence:
            return

        value = self.synthetic_175_sequence[self.synthetic_175_index]
        self.synthetic_175_index = (self.synthetic_175_index + 1) % len(self.synthetic_175_sequence)

        payload = bytearray(8)
        payload[6] = value & 0xFF
        payload[7] = (value + 0x76) & 0xFF
        self.can_bus.send(can.Message(arbitration_id=0x175, data=payload, is_extended_id=False))

    def send_186_message(self):
        if self._send_reference_message(0x186):
            return

        speed_scaled = int(max(0.0, min(255.0, self.actual_speed_kph * 2.0)))
        torque_scaled = int(max(0.0, min(255.0, abs(self.steering_torque_nm) * 3.0)))
        payload = bytearray(8)
        payload[0] = 0x80 | ((int(self.actual_speed_kph) // 4) & 0x1F)
        payload[1] = (self.di_torque2_counter + self.synthetic_1d8_index) & 0x0F
        payload[3] = 0x02
        payload[5] = speed_scaled
        payload[6] = torque_scaled
        self.can_bus.send(can.Message(arbitration_id=0x186, data=payload, is_extended_id=False))

    def send_1D8_message(self):
        if self._send_reference_message(0x1D8):
            return

        if not self.synthetic_1d8_sequence:
            return

        value = self.synthetic_1d8_sequence[self.synthetic_1d8_index]
        self.synthetic_1d8_index = (self.synthetic_1d8_index + 1) % len(self.synthetic_1d8_sequence)

        payload = bytearray(8)
        payload[6] = value & 0xFF
        payload[7] = (value + 0xD9) & 0xFF
        self.can_bus.send(can.Message(arbitration_id=0x1D8, data=payload, is_extended_id=False))

    def send_101_message(self):
        if self.msg_101 is None:
            return

        power_mode = 1 if self.actual_speed_kph > 0.1 else 1
        signals = {
            "GTW_epasEmergencyOn": 0,
            "GTW_epasPowerMode": power_mode,
            "GTW_epasTuneRequest": 6,
            "GTW_epasControlType": 3,
            "GTW_epasLDWEnabled": 1,
            "GTW_epasControlCounter": self.epas_control_counter,
            "GTW_epasControlChecksum": 0,
        }

        payload = bytearray(self.msg_101.encode(signals))
        if len(payload) < 3:
            payload.extend(b"\x00" * (3 - len(payload)))

        checksum = (0x101 & 0xFF) + ((0x101 >> 8) & 0xFF) + payload[0] + payload[1]
        payload[2] = checksum & 0xFF

        payload.extend(b"\x00" * (8 - len(payload)))

        try:
            self.can_bus.send(
                can.Message(
                    arbitration_id=0x101,
                    data=payload,
                    is_extended_id=False,
                )
            )
        except Exception as exc:
            if self.debug:
                print(f"Send error for 0x101: {exc}")

        self.epas_control_counter = (self.epas_control_counter + 1) % 16

    def send_214_message(self):
        if self.msg_214 is None:
            return

        signals = {
            "EPB_epasEACAllow": 0,
            "EPB_epasControlCounter": self.epb_control_counter,
            "EPB_epasControlChecksum": 0,
        }

        payload = bytearray(self.msg_214.encode(signals))
        if len(payload) < 3:
            payload.extend(b"\x00" * (3 - len(payload)))

        checksum = (0x214 & 0xFF) + ((0x214 >> 8) & 0xFF) + payload[0] + payload[1]
        payload[2] = checksum & 0xFF

        payload.extend(b"\x00" * (8 - len(payload)))

        try:
            self.can_bus.send(
                can.Message(
                    arbitration_id=0x214,
                    data=payload,
                    is_extended_id=False,
                )
            )
        except Exception as exc:
            if self.debug:
                print(f"Send error for 0x214: {exc}")

        self.epb_control_counter = (self.epb_control_counter + 1) % 16

    def send_257_message(self):
        if self._send_reference_message(0x257):
            return

        base = 0x4300 + int(self.steering_angle_deg * 8.0)
        payload = bytearray(8)
        payload[0] = base & 0xFF
        payload[1] = (base >> 8) & 0xFF
        payload[2] = 0x1F
        payload[4] = 0x02
        payload[5] = 0xA0 if self.accel_active else 0x60
        payload[6] = 0x0F
        self.can_bus.send(can.Message(arbitration_id=0x257, data=payload, is_extended_id=False))

    def send_2C1_message(self):
        if self._send_reference_message(0x2C1):
            return

        if not self.synthetic_2c1_keys:
            return

        key = self.synthetic_2c1_keys[self.synthetic_2c1_index % len(self.synthetic_2c1_keys)]
        self.synthetic_2c1_index = (self.synthetic_2c1_index + 1) % len(self.synthetic_2c1_keys)
        payload = self.synthetic_2c1_frames.get(key, b"\x00" * 8)
        if len(payload) < 8:
            payload = payload + bytes(8 - len(payload))
        self.can_bus.send(can.Message(arbitration_id=0x2C1, data=payload, is_extended_id=False))

    def send_398_message(self):
        if self.gateway_raw_398_payload is not None:
            raw = self.gateway_raw_398_payload
            if len(raw) != 8:
                raise ValueError("gateway_raw_398_payload must be exactly 8 bytes")
            payload = raw
        else:
            if self.msg_398 is None:
                return

            signals = {
                "GTW_dasHw": self.gateway_das_hw,
                "GTW_unknown1": self.gateway_unknown1,
                "GTW_fourWheelDrive": 1 if self.force_awd else 0,
                "GTW_performanceConfig": self.gateway_performance_config,
                "GTW_unknown2": self.gateway_unknown2,
                "GTW_airSuspensionInstalled": self.gateway_air_suspension,
                "GTW_forwardRadarHw": self.gateway_forward_radar_hw,
                "GTW_parkAssistInstalled": self.gateway_park_assist,
                "GTW_country": self.gateway_country,
                "GTW_radarPosition": self.radarPosition,
                "GTW_bodyControlsType": self.gateway_body_controls_type,
                "GTW_rhd": self.gateway_rhd,
                "GTW_parkSensorGeometryType": self.gateway_park_sensor_geometry,
                "GTW_chassisType": self.gateway_chassis_type,
                "GTW_epasType": self.gateway_epas_type,
                "GTW_frontCornerRadarHw": self.gateway_front_corner_radar_hw,
                "GTW_rearCornerRadarHw": self.gateway_rear_corner_radar_hw,
                "GTW_rearSeatControllerMask": self.gateway_rear_seat_controller_mask,
                "GTW_wheelType": self.gateway_wheel_type,
                "GTW_unknown3": self.gateway_unknown3,
                "GTW_autopilot": self.gateway_autopilot_level,
                "GTW_brakeHwType": self.gateway_brake_hw_type,
                "GTW_foldingMirrorsInstalled": self.gateway_folding_mirrors,
                "GTW_euVehicle": self.gateway_eu_vehicle,
            }

            payload = bytearray(self.msg_398.encode(signals))
            if len(payload) < 8:
                payload.extend(b"\x00" * (8 - len(payload)))
            payload = payload[:8]

        self.can_bus.send(
            can.Message(arbitration_id=0x398, data=payload, is_extended_id=False)
        )

    def send_159_message(self):
        """Send 0x159 message (exactly like Panda)"""
        MLB = 0x004FFFFB
        MHB = 0x000007FF + (self.tesla_radar_x159_id << 12)
        cksm = self.add_tesla_cksm(MLB, MHB, 0xC, 7)
        MLB = MLB + (cksm << 24)
        self.tesla_radar_x159_id = (self.tesla_radar_x159_id + 1) % 16
        self.send_message(0x159, MLB, MHB, 8)

    def send_149_message(self):
        """Send 0x149 message (exactly like Panda)"""
        MLB = 0x6A022600
        MHB = 0x000F04AA + (self.tesla_radar_x149_id << 20)
        cksm = self.add_tesla_cksm(MLB, MHB, 0x46, 7)
        MHB = MHB + (cksm << 24)
        self.tesla_radar_x149_id = (self.tesla_radar_x149_id + 1) % 16
        self.send_message(0x149, MLB, MHB, 8)

    def send_129_message(self):
        """Send 0x129 message (exactly like Panda)"""
        MLB = 0x20000000
        MHB = 0x00 + (self.tesla_radar_x129_id << 4)
        cksm = self.add_tesla_cksm(MLB, MHB, 0x16, 5)
        MHB = MHB + (cksm << 8)
        self.tesla_radar_x129_id = (self.tesla_radar_x129_id + 1) % 16
        self.send_message(0x129, MLB, MHB, 6)

    def send_1A9_message(self):
        """Send 0x1A9 message (exactly like Panda)"""
        MLB = 0x000C0000 + (self.tesla_radar_x1A9_id << 28)
        MHB = 0x00
        cksm = self.add_tesla_cksm(MLB, MHB, 0x38, 4)
        MHB = MHB + cksm
        self.tesla_radar_x1A9_id = (self.tesla_radar_x1A9_id + 1) % 16
        self.send_message(0x1A9, MLB, MHB, 5)

    def send_209_message(self):
        """Send 0x209 message (exactly like Panda)"""
        MLB = 0x5294FF00
        MHB = 0x00800313
        self.send_message(0x209, MLB, MHB, 8)

    def send_219_message(self):
        """Send 0x219 message (exactly like Panda)"""
        MLB = 0x00000000
        MHB = 0x00000000 + (self.tesla_radar_x219_id << 20)
        crc = self.add_tesla_crc(MLB, MHB, 7)
        MHB = MHB + (crc << 24)
        self.tesla_radar_x219_id = (self.tesla_radar_x219_id + 1) % 16
        self.send_message(0x219, MLB, MHB, 8)

    def send_17C_message(self):
        """Send 0x17C driver status heartbeat message (simplified)."""
        data = bytearray(8)
        data[0] = 0x80 if self.brake_active else 0x00
        data[1] = 0x40 if self.accel_active else 0x00
        data[2] = self.gear_state & 0xFF
        data[3] = int(max(0.0, min(255.0, self.actual_speed_kph)))
        data[4] = int(max(0.0, min(255.0, self.actual_speed_kph * 2.0)))
        data[5] = (self.turn_indicator & 0x03) << 6
        data_low = int.from_bytes(data[:4], "little")
        data_high = int.from_bytes(data[4:], "little")
        self.send_message(0x17C, data_low, data_high, 8)

    def send_2B9_message(self):
        """Send 0x2B9 VIN message (exactly like Panda) - 3 part transmission"""
        rec = 0x10 + self.tesla_radar_x2B9_id

        if rec == 0x10:  # First part
            MLB = 0x00000000 | rec
            MHB = (
                self.radar_VIN_char(0, 1)
                | self.radar_VIN_char(1, 2)
                | self.radar_VIN_char(2, 3)
            )
        elif rec == 0x11:  # Second part
            MLB = (
                rec
                | self.radar_VIN_char(3, 1)
                | self.radar_VIN_char(4, 2)
                | self.radar_VIN_char(5, 3)
            )
            MHB = (
                self.radar_VIN_char(6, 0)
                | self.radar_VIN_char(7, 1)
                | self.radar_VIN_char(8, 2)
                | self.radar_VIN_char(9, 3)
            )
        elif rec == 0x12:  # Third part
            MLB = (
                rec
                | self.radar_VIN_char(10, 1)
                | self.radar_VIN_char(11, 2)
                | self.radar_VIN_char(12, 3)
            )
            MHB = (
                self.radar_VIN_char(13, 0)
                | self.radar_VIN_char(14, 1)
                | self.radar_VIN_char(15, 2)
                | self.radar_VIN_char(16, 3)
            )
        else:
            return

        self.tesla_radar_x2B9_id = (self.tesla_radar_x2B9_id + 1) % 3
        self.send_message(0x2B9, MLB, MHB, 8)

        # Track VIN completion
        if rec == 0x12:  # Completed third part
            self.tesla_radar_vin_complete = min(self.tesla_radar_vin_complete + 1, 7)
            if self.debug:
                print(f"VIN transmission cycle: {self.tesla_radar_vin_complete}/7")

    def send_508_messages(self):
        """Send 0x508 VIN frames (gateway format) so bench traffic matches vehicle."""
        vin = self.radar_VIN.ljust(17)
        chunks = [vin[0:7], vin[7:14], vin[14:17]]
        for index, chunk in enumerate(chunks):
            payload = bytearray(8)
            payload[0] = index
            for offset, char in enumerate(chunk):
                payload[offset + 1] = ord(char)
            self.can_bus.send(
                can.Message(arbitration_id=0x508, data=payload, is_extended_id=False)
            )

    def send_2A9_message(self):
        """Send 0x2A9 radar config message (exactly like Panda)"""
        MLB = 0x41431642
        MHB = 0x10020000 | (self.radarPosition << 4) | (self.radarEpasType << 12)

        # Check for AWD (position 8 of VIN is '2' for dual motor)
        if self.force_awd or (len(self.radar_VIN) >= 8 and self.radar_VIN[7] == "2"):
            MLB = MLB | 0x08

        self.send_message(0x2A9, MLB, MHB, 8)

    def send_2D9_message(self):
        """Send 0x2D9 message (exactly like Panda)"""
        MLB = 0x00834080
        MHB = 0x00000000
        self.send_message(0x2D9, MLB, MHB, 8)

    def monitor_radar_responses(self):
        """Monitor radar responses and update state"""
        while self.running:
            try:
                msg = self.can_bus.recv(timeout=0.1)
            except (ValueError, IndexError) as err:
                if self.debug:
                    print(f"CAN decode error: {err}")
                continue
            except can.CanError as err:
                if self.debug:
                    print(f"CAN error: {err}")
                time.sleep(0.1)
                continue
            if msg is not None:
                msg_id = msg.arbitration_id

                # Monitor 0x631 (radar initialization)
                if msg_id == 0x631:
                    if self.tesla_radar_status == 0:
                        self.tesla_radar_status = 1
                        self.last_radar_signal = time.time()
                        print("🔄 Tesla Radar Initializing...")
                    elif self.tesla_radar_status > 0:
                        self.last_radar_signal = time.time()
                    self.init_message_count += 1
                    self.last_init_data = bytes(msg.data)

                # Monitor 0x300 (radar status)
                elif msg_id == 0x300:
                    if self.tesla_radar_status == 1:
                        self.tesla_radar_status = 2
                        print("🎯 Tesla Radar Active! (Plant mode exited)")
                    elif self.tesla_radar_status == 2:
                        self.last_radar_signal = time.time()
                    self.status_message_count += 1
                    self.last_status_data = bytes(msg.data)

                elif msg_id == 0x3FF:
                    self.last_system_status_data = bytes(msg.data)
                    if len(msg.data) >= 2:
                        error_code = msg.data[1]
                        if error_code != 0:
                            self.error_code_counts[error_code] += 1
                            self.error_code_payloads[error_code].add(msg.data.hex())
                            description = self.plant_failure_map.get(
                                int(error_code), "UNKNOWN"
                            )
                            if self.debug:
                                print(
                                    "⚠️  ERROR CODE (0x3FF): "
                                    f"{error_code} ({description}) "
                                    f"payload={msg.data.hex()}"
                                )
                                print(
                                    "    [debug] error_code_counts:",
                                    dict(self.error_code_counts)
                                )

                # Debug: show received messages
                if self.debug and msg_id in [0x300, 0x631]:
                    print(f"RX: 0x{msg_id:03X} = {msg.data.hex()}")

                # Check for timeout
                if (
                    time.time() - self.last_radar_signal > 1.0
                    and self.tesla_radar_status > 0
                ):
                    print("❌ Tesla Radar Timeout!")
                    self.tesla_radar_status = 0

    def start(self):
        """Start the Tesla radar protocol"""
        self.running = True
        self.start_time = time.time()
        self.last_radar_signal = time.time()
        self.simulation_start_ts = self.start_time

        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_radar_responses)
        monitor_thread.daemon = True
        monitor_thread.start()

        print("🚀 Tesla Radar Protocol Started")
        print(f"   VIN: {self.radar_VIN}")
        print(f"   Position: {self.radarPosition}, EPAS: {self.radarEpasType}")
        print(f"   Speed: {self.actual_speed_kph} km/h")

        # Main transmission loop at 100Hz
        while self.running:
            loop_start = time.time()

            try:
                self._update_vehicle_state()
                self.base_speed_kph = self.actual_speed_kph
                self.activate_tesla_radar()

                # Status updates
                if self.tesla_radar_counter % 100 == 0:  # Every 1 second
                    elapsed = time.time() - self.start_time
                    status_names = {0: "Not Present", 1: "Initializing", 2: "Active"}
                    print(
                        f"Status: {status_names[self.tesla_radar_status]}, "
                        f"VIN: {self.tesla_radar_vin_complete}/7, "
                        f"Time: {elapsed:.1f}s"
                    )

                # Sleep to maintain 100Hz
                sleep_time = 0.01 - (time.time() - loop_start)
                if sleep_time > 0:
                    time.sleep(sleep_time)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Protocol error: {e}")
                time.sleep(0.1)

    def stop(self):
        """Stop the Tesla radar protocol"""
        self.running = False
        print("🛑 Tesla Radar Protocol Stopped")

    def _generate_wheel_speeds(self):
        """Generate a plausible wheel-speed profile in km/h for FR/FL/RR/RL."""
        now = time.time()
        sim_t = now - self.simulation_start_ts
        base = self.actual_speed_kph
        modulation = 5.0 * math.sin(sim_t / 5.0)
        steer_component = 3.0 * math.sin(sim_t / 3.0)
        steering_angle = 20.0 * math.sin(sim_t / 2.5)
        self.steering_angle_deg = steering_angle
        self.steering_rate_dps = 20.0 * math.cos(sim_t / 2.5)
        self.steering_torque_nm = 5.0 * math.sin(sim_t / 1.8)
        # Slight rear axle lag
        rear_phase = math.sin((sim_t / 4.0) + math.pi / 6)

        frl = max(0.0, base + modulation + steer_component)
        frr = max(0.0, base + modulation - steer_component)
        rrl = max(0.0, base + modulation * 0.8 + rear_phase * 3.0)
        rrr = max(0.0, base + modulation * 0.8 - rear_phase * 3.0)
        return [frl, frr, rrl, rrr]

    def describe_error_code(self, code):
        return self.plant_failure_map.get(int(code), "UNKNOWN")


if __name__ == "__main__":
    # Test the protocol
    can_bus = setup_can(interface="can1")

    try:
        protocol = TeslaRadarProtocol(can_bus, debug=True)
        protocol.start()
    except KeyboardInterrupt:
        print("\n🛑 Protocol stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        protocol.stop()
        can_bus.shutdown()
        print("CAN interface closed")
def get_plant_failure_map():
    """Return a copy of the cached plant failure mapping."""
    return _load_plant_failure_map().copy()


def _load_plant_failure_map():
    global _PLANT_FAILURE_MAP
    if _PLANT_FAILURE_MAP is not None:
        return _PLANT_FAILURE_MAP

    base_dir = Path(__file__).resolve().parent
    candidates = [
        base_dir / "tesla_odj" / "Model S" / "RADC.odj.json",
        base_dir.parent / "references" / "tesla_odj" / "Model S" / "RADC.odj.json",
        Path.cwd() / "references" / "tesla_odj" / "Model S" / "RADC.odj.json",
    ]

    radc_path = next((path for path in candidates if path.exists()), None)
    if radc_path is None:
        _PLANT_FAILURE_MAP = {}
        return _PLANT_FAILURE_MAP

    try:
        with radc_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        enum_map = (
            data.get("routines", {})
            .get("PLANT_MODE", {})
            .get("results", {})
            .get("output", {})
            .get("PLANT_MODE_FAILURE_STATUS", {})
            .get("map", {})
            .get("enum", {})
        )
        # Invert to value -> description, ensuring integers
        inverted = {}
        for name, value in enum_map.items():
            try:
                inverted[int(value)] = name
            except (ValueError, TypeError):
                continue
        _PLANT_FAILURE_MAP = inverted
    except Exception:
        _PLANT_FAILURE_MAP = {}

    return _PLANT_FAILURE_MAP
