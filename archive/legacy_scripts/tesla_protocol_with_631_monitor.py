#!/usr/bin/env python3
"""
Tesla Protocol with 0x631 Monitor
=================================

Combined Tesla radar protocol emulator and 0x631 initialization monitor.
This single process both sends Tesla messages AND monitors for 0x631 responses.

Since only one process can access the CAN bus at a time, this integrated
approach allows us to:
1. Send the Tesla protocol messages that activate the radar
2. Monitor for 0x631 initialization responses in the same process
3. Track radar power increases and initialization sequence
4. Detect full radar activation and startup completion

Usage:
    python3 tesla_protocol_with_631_monitor.py
"""

import can
import time
import signal
import sys
import struct
from collections import defaultdict, deque
from datetime import datetime


class TeslaProtocolWith631Monitor:
    """Combined Tesla protocol sender and 0x631 monitor"""

    def __init__(self, can_interface: str = "can0"):
        self.can_interface = can_interface
        self.bus = None
        self.running = False
        self.start_time = time.time()

        # Tesla protocol variables
        self.speed_kph = 25
        self.radar_vin = "5YJSB7E43GF113105"
        self.tesla_radar_counter = 0
        self.tesla_radar_trigger_message_id = 0x17C

        # Tesla radar state variables (from tesla_radar.h)
        self.tesla_radar_vin_complete = 7
        self.tesla_radar_should_send = 1
        self.radarPosition = 1
        self.radarEpasType = 2

        # Message counters (EXACT from tesla_radar.h)
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

        # 0x631 monitoring variables
        self.x631_messages = []
        self.x631_first_seen = None
        self.x631_count = 0
        self.x631_patterns = defaultdict(int)

        # Radar state tracking
        self.radar_states = deque(maxlen=100)
        self.power_levels = deque(maxlen=100)
        self.scan_indices = deque(maxlen=100)

        # Initialization phases
        self.initialization_phases = {
            "protocol_started": False,
            "power_increase": False,
            "x631_detected": False,
            "scanning_active": False,
            "fully_operational": False,
        }

        # CRC lookup table (from tesla_radar.h)
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

    def setup_can(self) -> bool:
        """Setup CAN interface"""
        try:
            self.bus = can.interface.Bus(
                channel=self.can_interface, interface="socketcan"
            )
            print(f"✅ CAN interface {self.can_interface} setup successful")
            return True
        except Exception as e:
            print(f"❌ CAN interface setup failed: {e}")
            return False

    def add_tesla_crc(self, MLB, MHB, msg_len):
        """Calculate CRC8 using 1D poly, FF start, FF end"""
        crc = 0xFF
        for x in range(msg_len):
            if x <= 3:
                v = (MLB >> (x * 8)) & 0xFF
            else:
                v = (MHB >> ((x - 4) * 8)) & 0xFF
            crc = self.crc_lookup[crc ^ v]
        crc = crc ^ 0xFF
        return crc

    def add_tesla_cksm2(self, dl, dh, msg_id, msg_len):
        """Calculate Tesla checksum"""
        cksm = (0xFF & msg_id) + (0xFF & (msg_id >> 8))
        for x in range(msg_len):
            if x <= 3:
                v = (dl >> (x * 8)) & 0xFF
            else:
                v = (dh >> ((x - 4) * 8)) & 0xFF
            cksm = (cksm + v) & 0xFF
        return cksm

    def radar_VIN_char(self, pos, shift):
        """Get VIN character at position with shift"""
        if pos < len(self.radar_vin):
            return ord(self.radar_vin[pos]) << (shift * 8)
        return 0

    def send_tesla_message(self, msg_addr, msg_len, data_lo, data_hi):
        """Send Tesla CAN message with error handling"""
        try:
            # Convert to 8-byte array
            data = []
            for i in range(8):
                if i < 4:
                    data.append((data_lo >> (i * 8)) & 0xFF)
                else:
                    data.append((data_hi >> ((i - 4) * 8)) & 0xFF)

            # Truncate to actual message length
            data = data[:msg_len]

            msg = can.Message(arbitration_id=msg_addr, data=data, is_extended_id=False)
            self.bus.send(msg)
            return True

        except Exception as e:
            # Don't spam errors, just return False
            return False

    def send_core_tesla_messages(self):
        """Send only the core Tesla messages to avoid buffer overflow"""
        if (self.tesla_radar_vin_complete != 7) or (self.tesla_radar_should_send == 0):
            return

        # Send only the most critical messages at reduced rate

        # 0x199 - Critical vehicle status
        MLB = 0x00207D2F
        MHB = 0x0000FF04 + (self.tesla_radar_x199_id << 20)
        crc = self.add_tesla_crc(MLB, MHB, 7)
        MHB = MHB + (crc << 24)
        self.tesla_radar_x199_id = (self.tesla_radar_x199_id + 1) % 16
        self.send_tesla_message(0x199, 8, MLB, MHB)

        # 0x169 - Speed data (CRITICAL for activation!)
        speed_kph = int(self.speed_kph / 0.04) & 0x1FFF
        MLB = (speed_kph | (speed_kph << 13) | (speed_kph << 26)) & 0xFFFFFFFF
        MHB = (
            (speed_kph >> 6) | (speed_kph << 7) | (self.tesla_radar_x169_id << 20)
        ) & 0x00FFFFFF
        cksm = self.add_tesla_cksm2(MLB, MHB, 0x76, 7)
        MHB = MHB + (cksm << 24)
        self.tesla_radar_x169_id = (self.tesla_radar_x169_id + 1) % 16
        self.send_tesla_message(0x169, 8, MLB, MHB)

        # 0x119 - System status
        MLB = 0x11F41FFF
        MHB = 0x00000080 + self.tesla_radar_x119_id
        cksm = self.add_tesla_cksm2(MLB, MHB, 0x17, 5)
        MHB = MHB + (cksm << 8)
        self.tesla_radar_x119_id = (self.tesla_radar_x119_id + 1) % 16
        self.send_tesla_message(0x119, 6, MLB, MHB)

        # 0x109 - Control messages
        MLB = 0x80000000 + (self.tesla_radar_x109_id << 13)
        MHB = 0x00
        cksm = self.add_tesla_cksm2(MLB, MHB, 0x7, 7)
        MHB = MHB + (cksm << 24)
        self.tesla_radar_x109_id = (self.tesla_radar_x109_id + 1) % 8
        self.send_tesla_message(0x109, 8, MLB, MHB)

        # Send VIN every 25 cycles (4Hz equivalent)
        if self.tesla_radar_counter % 25 == 0:
            # Send 0x2B9 (VIN transmission)
            rec = 0x10 + self.tesla_radar_x2B9_id
            if rec == 0x10:
                MLB = 0x00000000 | rec
                MHB = (
                    self.radar_VIN_char(0, 1)
                    | self.radar_VIN_char(1, 2)
                    | self.radar_VIN_char(2, 3)
                )
            elif rec == 0x11:
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
            elif rec == 0x12:
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

            self.tesla_radar_x2B9_id = (self.tesla_radar_x2B9_id + 1) % 3
            self.send_tesla_message(0x2B9, 8, MLB, MHB)

        self.tesla_radar_counter = (self.tesla_radar_counter + 1) % 100

    def analyze_0x631_message(self, msg):
        """Detailed analysis of 0x631 initialization messages"""
        current_time = time.time()
        elapsed = current_time - self.start_time

        if self.x631_first_seen is None:
            self.x631_first_seen = current_time
            print(f"\n🎉 FIRST 0x631 INITIALIZATION MESSAGE DETECTED!")
            print(f"   Time: {elapsed:.1f}s after protocol start")
            print(f"   Timestamp: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
            self.initialization_phases["x631_detected"] = True

        self.x631_count += 1
        data_hex = msg.data.hex().upper()
        self.x631_patterns[data_hex] += 1

        print(f"🔥 0x631 #{self.x631_count} at {elapsed:.1f}s: {data_hex}")

        # Analyze data content
        if len(msg.data) >= 8:
            try:
                word1 = struct.unpack("<I", msg.data[0:4])[0]
                word2 = struct.unpack("<I", msg.data[4:8])[0]
                print(f"   Data: Word1=0x{word1:08X}, Word2=0x{word2:08X}")

                # Look for specific initialization patterns
                if word1 == 0x00000000 and word2 == 0x00000000:
                    print("   🔍 Pattern: All zeros - possible reset/init")
                elif word1 != 0x00000000 or word2 != 0x00000000:
                    print("   🔍 Pattern: Non-zero data - possible config/status")

            except Exception as e:
                print(f"   ⚠️  Data decode error: {e}")

    def analyze_radar_status(self, msg):
        """Analyze 0x300 radar status messages"""
        if len(msg.data) >= 8:
            try:
                radar_state = msg.data[0] & 0x0F
                power_level = msg.data[2] if len(msg.data) > 2 else 0
                scan_index = msg.data[1] if len(msg.data) > 1 else 0

                # Track state changes
                self.power_levels.append(power_level)
                self.scan_indices.append(scan_index)

                # Detect power increase
                if len(self.power_levels) > 1:
                    prev_power = self.power_levels[-2]
                    if (
                        power_level > prev_power
                        and not self.initialization_phases["power_increase"]
                    ):
                        elapsed = time.time() - self.start_time
                        print(
                            f"⚡ POWER INCREASE: {prev_power} → {power_level} at {elapsed:.1f}s"
                        )
                        self.initialization_phases["power_increase"] = True

                # Check for active scanning
                if len(self.scan_indices) > 10:
                    recent_indices = list(self.scan_indices)[-10:]
                    unique_indices = len(set(recent_indices))
                    if (
                        unique_indices > 3
                        and not self.initialization_phases["scanning_active"]
                    ):
                        self.initialization_phases["scanning_active"] = True
                        elapsed = time.time() - self.start_time
                        print(f"📡 ACTIVE SCANNING DETECTED at {elapsed:.1f}s!")

            except Exception as e:
                print(f"⚠️  Error analyzing 0x300: {e}")

    def check_messages(self):
        """Check for incoming messages (non-blocking)"""
        try:
            msg = self.bus.recv(timeout=0.001)  # Very short timeout
            if msg is not None:
                msg_id = msg.arbitration_id

                # Monitor for critical messages
                if msg_id == 0x631:
                    self.analyze_0x631_message(msg)
                elif msg_id == 0x300:
                    self.analyze_radar_status(msg)

        except Exception:
            # No message available, continue
            pass

    def print_status_update(self):
        """Print status update"""
        elapsed = time.time() - self.start_time

        print(f"\n📊 STATUS UPDATE - {elapsed:.1f}s elapsed")
        print("=" * 50)

        # 0x631 status
        if self.x631_count > 0:
            print(f"🔥 0x631 MESSAGES: {self.x631_count} detected")
            print(f"   Unique patterns: {len(self.x631_patterns)}")
        else:
            print("❌ 0x631 INITIALIZATION: NOT DETECTED")

        # Power status
        if self.power_levels:
            current_power = max(self.power_levels) if self.power_levels else 0
            print(f"⚡ MAX POWER LEVEL: {current_power}")

        # Initialization phases
        print("🔄 PHASES:")
        for phase, status in self.initialization_phases.items():
            status_icon = "✅" if status else "⏳"
            print(f"   {status_icon} {phase.replace('_', ' ').title()}")

    def run(self):
        """Main combined protocol and monitoring loop"""
        if not self.setup_can():
            return False

        self.running = True
        self.initialization_phases["protocol_started"] = True

        def signal_handler(sig, frame):
            print("\n🛑 Stopping Tesla Protocol with 0x631 Monitor...")
            self.running = False
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        print("🚗 Tesla Protocol with 0x631 Monitor")
        print("=" * 50)
        print("🎯 Combined Tesla protocol sender and 0x631 detector")
        print("📡 Sends Tesla messages AND monitors for 0x631 responses")
        print("⚡ Designed to detect radar initialization sequence")
        print(f"   VIN: {self.radar_vin}")
        print(f"   Speed: {self.speed_kph} km/h")
        print()

        last_protocol_send = 0
        last_status_update = 0

        try:
            while self.running:
                current_time = time.time()

                # Send Tesla protocol at reduced rate (20Hz instead of 100Hz)
                if current_time - last_protocol_send >= 0.05:  # 20Hz
                    self.send_core_tesla_messages()
                    last_protocol_send = current_time

                # Check for incoming messages
                self.check_messages()

                # Status updates every 15 seconds
                if current_time - last_status_update >= 15.0:
                    self.print_status_update()
                    last_status_update = current_time

                # Small delay to prevent overwhelming the system
                time.sleep(0.01)

        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            if self.bus:
                self.bus.shutdown()

        return True


def main():
    """Main function"""
    protocol = TeslaProtocolWith631Monitor("can0")

    print("🔧 Tesla Protocol with 0x631 Monitor")
    print("=" * 50)
    print("🎯 Combined Tesla protocol and 0x631 initialization detector")
    print("📡 Single process solution for CAN bus access")
    print("⚡ Sends Tesla messages AND monitors for radar responses")
    print("🔥 Specifically designed to detect 0x631 initialization!")
    print()

    protocol.run()


if __name__ == "__main__":
    main()
