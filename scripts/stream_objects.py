#!/usr/bin/env python3
"""
Tesla Bosch MRRevo14F Radar — Object Stream using Proven Protocol

Uses the full TeslaRadarProtocol (all ~30 message types, threaded TX+RX)
which is proven to keep the radar active. Patches the RX monitor to also
decode radar objects and track scan/error state.

Usage:
    DYLD_LIBRARY_PATH=/opt/homebrew/opt/libusb/lib python3 scripts/stream_objects.py

Run PSU monitor in a separate terminal:
    python3 scripts/psu_monitor.py
"""

import argparse
import sys
import time
import threading
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.protocol.tesla_radar_protocol import TeslaRadarProtocol, setup_can, _load_radar_dbc

NUM_OBJECTS = 32
OBJ_BASE = 0x310
OBJ_A_IDS = {OBJ_BASE + i * 3 for i in range(NUM_OBJECTS)}
OBJ_B_IDS = {OBJ_BASE + i * 3 + 1 for i in range(NUM_OBJECTS)}

POWER_SERIAL = "/dev/cu.usbserial-2210"


def power_cycle():
    """Power cycle via SCPI."""
    import serial
    print("Power cycling radar...")
    with serial.Serial(POWER_SERIAL, 115200, timeout=1) as ser:
        ser.write(b"OUTP 0\r\n")
        ser.flush()
        time.sleep(1.5)
        ser.write(b"OUTP 1\r\n")
        ser.flush()
    time.sleep(3.0)
    print("Power on, waiting for radar boot...")


class ObjectTracker:
    """Thread-safe object state shared between RX monitor and print thread."""

    def __init__(self):
        self.lock = threading.Lock()
        self.a_frames = {}
        self.b_frames = {}
        self.objects = {}  # obj_idx -> {dist, speed, lat, prob, valid, ...}
        self.scan_indices = set()
        self.error_codes = set()
        self.last_scan_idx = None
        self.last_power_level = None
        self.status_count = 0
        self.init_count = 0

    def update_status(self, msg_data):
        with self.lock:
            self.status_count += 1
            if len(msg_data) >= 2:
                self.last_scan_idx = msg_data[1]
                self.scan_indices.add(msg_data[1])
            if len(msg_data) >= 3:
                self.last_power_level = msg_data[2]

    def update_init(self):
        with self.lock:
            self.init_count += 1

    def update_error(self, msg_data):
        with self.lock:
            # byte[0] = message subtype, byte[1] = error bitmask
            if len(msg_data) >= 2 and msg_data[1] != 0:
                self.error_codes.add(msg_data[1])

    def update_object(self, obj_idx, a_data, b_data):
        with self.lock:
            self.objects[obj_idx] = {
                "dist": a_data.get("LongDist", 0),
                "speed": a_data.get("LongSpeed", 0),
                "lat": a_data.get("LatDist", 0),
                "prob": a_data.get("ProbExist", 0),
                "valid": int(a_data.get("Valid", 0)),
                "tracked": int(a_data.get("Tracked", 0)),
                "meas": int(a_data.get("Meas", 0)),
                "idx_a": int(a_data.get("Index", -1)),
                "idx_b": int(b_data.get("Index2", -1)),
                "class": int(b_data.get("Class", 0)),
                "mov": int(b_data.get("MovingState", 0)),
                "time": time.time(),
            }

    def get_snapshot(self):
        with self.lock:
            return {
                "objects": dict(self.objects),
                "scan_indices": set(self.scan_indices),
                "error_codes": set(self.error_codes),
                "last_scan_idx": self.last_scan_idx,
                "last_power_level": self.last_power_level,
                "status_count": self.status_count,
                "init_count": self.init_count,
            }


def make_patched_monitor(protocol, tracker, dbc):
    """Create a patched monitor_radar_responses that also decodes objects."""

    # Pre-load DBC message definitions for all object IDs
    a_msg_def = {}
    b_msg_def = {}
    for i in range(NUM_OBJECTS):
        a_id = OBJ_BASE + i * 3
        b_id = OBJ_BASE + i * 3 + 1
        try:
            a_msg_def[a_id] = dbc.get_message_by_frame_id(a_id)
        except KeyError:
            a_msg_def[a_id] = dbc.get_message_by_frame_id(OBJ_BASE)
        try:
            b_msg_def[b_id] = dbc.get_message_by_frame_id(b_id)
        except KeyError:
            b_msg_def[b_id] = dbc.get_message_by_frame_id(OBJ_BASE + 1)

    a_frames = {}
    b_frames = {}

    def patched_monitor():
        """RX monitor: handles protocol state + object decoding."""
        import can

        while protocol.running:
            try:
                msg = protocol.can_bus.recv(timeout=0.1)
            except (ValueError, IndexError):
                continue
            except can.CanError:
                time.sleep(0.1)
                continue

            if msg is None:
                # Timeout — check for radar sleep
                elapsed = time.time() - protocol.last_radar_signal
                if elapsed > 1.0 and protocol.tesla_radar_status > 0:
                    protocol.tesla_radar_status = 0
                continue

            mid = msg.arbitration_id

            # -- Original protocol state tracking --
            if mid == 0x631:
                if protocol.tesla_radar_status == 0:
                    protocol.tesla_radar_status = 1
                    protocol.last_radar_signal = time.time()
                elif protocol.tesla_radar_status > 0:
                    protocol.last_radar_signal = time.time()
                protocol.init_message_count += 1
                protocol.last_init_data = bytes(msg.data)
                tracker.update_init()

            elif mid == 0x300:
                if protocol.tesla_radar_status == 1:
                    protocol.tesla_radar_status = 2
                    protocol.last_radar_signal = time.time()
                elif protocol.tesla_radar_status == 2:
                    protocol.last_radar_signal = time.time()
                protocol.status_message_count += 1
                protocol.last_status_data = bytes(msg.data)
                tracker.update_status(msg.data)

            elif mid == 0x3FF:
                protocol.last_system_status_data = bytes(msg.data)
                if len(msg.data) >= 2:
                    error_code = msg.data[1]
                    if error_code != 0:
                        protocol.error_code_counts[error_code] += 1
                tracker.update_error(msg.data)

            # -- Object decoding --
            elif mid in OBJ_A_IDS:
                obj_idx = (mid - OBJ_BASE) // 3
                try:
                    a_frames[obj_idx] = a_msg_def[mid].decode(msg.data)
                except Exception:
                    pass

            elif mid in OBJ_B_IDS:
                obj_idx = (mid - OBJ_BASE) // 3
                try:
                    b_data = b_msg_def[mid].decode(msg.data)
                except Exception:
                    continue

                if obj_idx in a_frames:
                    tracker.update_object(obj_idx, a_frames[obj_idx], b_data)

    return patched_monitor


def parse_args():
    p = argparse.ArgumentParser(
        description="Tesla Radar Object Stream (full protocol, threaded)"
    )
    p.add_argument("--no-power-cycle", action="store_true")
    p.add_argument("--show-all", action="store_true", help="Show all objects including ghosts")
    p.add_argument("--can-interface", default="can0")
    p.add_argument("--rate", type=float, default=2.0, help="Print rate in Hz")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    dbc = _load_radar_dbc()

    print("=" * 65)
    print("Tesla Radar Object Stream — Full Protocol (Threaded TX+RX)")
    print("=" * 65)

    bus = setup_can(interface=args.can_interface)

    if not args.no_power_cycle:
        power_cycle()

    # Create protocol with default config
    protocol = TeslaRadarProtocol(bus, debug=args.debug)

    # Create shared object tracker
    tracker = ObjectTracker()

    # Patch the RX monitor to also decode objects
    protocol.monitor_radar_responses = make_patched_monitor(protocol, tracker, dbc)

    # Start protocol in background thread (TX loop + patched RX monitor)
    proto_thread = threading.Thread(target=protocol.start, daemon=True)
    proto_thread.start()

    print("Protocol started (TX: ~30 msg types at 100Hz, RX: objects + status)")
    print("Waiting for radar init...\n")

    # Main thread: print objects and status
    print_interval = 1.0 / args.rate
    last_print = {}  # obj_idx -> (dist, lat) for dedup
    started = time.time()
    header_printed = False

    try:
        while True:
            time.sleep(print_interval)
            elapsed = time.time() - started
            snap = tracker.get_snapshot()

            # Wait for init period
            if elapsed < 7.0:
                continue

            if not header_printed:
                header_printed = True
                err_str = ",".join(f"0x{c:02X}" for c in sorted(snap["error_codes"])) if snap["error_codes"] else "none"
                print(f"Init: 0x631={snap['init_count']} | Status: 0x300={snap['status_count']} | Scans:{len(snap['scan_indices'])} | Errors:{err_str}")
                status_names = {0: "Not Present", 1: "Initializing", 2: "Active"}
                print(f"Radar status: {status_names.get(protocol.tesla_radar_status, '?')}")
                print(f"Speed simulation: 0-120 kph cycling (60s period)")
                print()
                hdr = (
                    f"{'Time':>12} {'Obj':>3} {'Dist':>7} {'Speed':>7} {'Lat':>7} "
                    f"{'Prob%':>6} {'V':>1} {'T':>1} {'M':>1} {'Idx':>3} "
                    f"{'Class':>5} {'Mov':>3}"
                )
                print(hdr)
                print("-" * len(hdr))

            # Print objects
            printed_any = False
            for obj_idx in sorted(snap["objects"].keys()):
                obj = snap["objects"][obj_idx]
                dist = obj["dist"]
                prob = obj["prob"]
                valid = obj["valid"]
                tracked = obj["tracked"]

                # Filter noise
                if not args.show_all:
                    if dist == 0 and prob == 0 and not valid:
                        if obj_idx in last_print:
                            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                            print(f"{ts:>12} {obj_idx:3d}    -- gone --")
                            del last_print[obj_idx]
                        continue
                    if prob < 1.0 and not valid:
                        continue

                # Dedup
                new_val = (round(dist, 1), round(obj["lat"], 1))
                if not args.show_all and last_print.get(obj_idx) == new_val:
                    continue
                last_print[obj_idx] = new_val

                idx_match = "=" if obj["idx_a"] == obj["idx_b"] else "!"
                flags = ""
                if prob >= 50 and valid and tracked and dist > 0:
                    flags = " CONFIRMED"
                elif prob >= 20 and (valid or tracked) and dist > 0:
                    flags = " weak"
                elif dist > 0:
                    flags = " ghost"

                ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                line = (
                    f"{ts:>12} {obj_idx:3d} {dist:7.1f} {obj['speed']:7.1f} {obj['lat']:7.2f} "
                    f"{prob:6.1f} {valid} {tracked} {obj['meas']} {idx_match:>3} "
                    f"{obj['class']:5d} {obj['mov']:3d}"
                )
                line += flags
                print(line, flush=True)
                printed_any = True

            # Periodic status (every ~5s when no objects)
            if not printed_any and int(elapsed) % 5 == 0 and elapsed > 8:
                err_str = ",".join(f"0x{c:02X}" for c in sorted(snap["error_codes"])) if snap["error_codes"] else "none"
                status_names = {0: "NOT PRESENT", 1: "INIT", 2: "ACTIVE"}
                st = status_names.get(protocol.tesla_radar_status, "?")
                print(
                    f"  [{elapsed:.0f}s] {st} scan={snap['last_scan_idx']} "
                    f"pwr={snap['last_power_level']} scans={len(snap['scan_indices'])} "
                    f"errs={err_str} spd={protocol.actual_speed_kph:.0f}kph",
                    flush=True,
                )

    except KeyboardInterrupt:
        print("\n\nStopping...")
    finally:
        protocol.stop()
        time.sleep(0.5)
        bus.shutdown()

        snap = tracker.get_snapshot()
        print()
        print("=" * 55)
        print("SESSION SUMMARY")
        print("=" * 55)
        print(f"  0x631 init msgs: {snap['init_count']}")
        print(f"  0x300 status msgs: {snap['status_count']}")
        print(f"  Unique scan indices: {len(snap['scan_indices'])}")
        if snap["scan_indices"]:
            vals = sorted(snap["scan_indices"])
            if len(vals) > 20:
                print(f"  Scan index range: {vals[0]}-{vals[-1]} ({len(vals)} unique)")
            else:
                print(f"  Scan index values: {vals}")
        print(f"  Error codes (0x3FF): {sorted(snap['error_codes']) if snap['error_codes'] else 'none'}")
        if snap["error_codes"]:
            bits = {0x08: "VIN", 0x10: "AIR_SUSP", 0x20: "EPAS", 0x40: "CHASSIS", 0x80: "BIT7"}
            all_bits = set()
            for code in snap["error_codes"]:
                for bit, name in bits.items():
                    if code & bit:
                        all_bits.add(name)
            print(f"  Error bit flags: {sorted(all_bits)}")
        objs = [k for k, v in snap["objects"].items() if v["dist"] > 0]
        print(f"  Objects with distance > 0: {sorted(objs) if objs else 'none'}")
        print()


if __name__ == "__main__":
    main()
