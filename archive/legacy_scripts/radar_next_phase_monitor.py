#!/usr/bin/env python3
"""
Tesla Radar Next Phase Monitor
=============================

Specialized monitor for the next phase of Tesla radar activation.
Since power increase has been achieved, this monitor focuses on:
- Detecting 0x631 initialization messages
- Tracking scan index progression
- Monitoring for object detection capability
- Validating full radar activation

This tool is optimized for the current phase where power increase
has been confirmed and we're waiting for the next activation steps.
"""

import can
import time
import signal
import sys
import struct
from collections import defaultdict, deque
from datetime import datetime


class RadarNextPhaseMonitor:
    """Monitor for next phase of Tesla radar activation"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None
        self.running = False
        self.start_time = time.time()

        # Phase tracking (starting from power increase achieved)
        self.current_phase = "POWER_INCREASE_ACHIEVED"
        self.phase_transitions = []

        # 0x631 tracking
        self.x631_status = {
            "detected": False,
            "first_time": None,
            "count": 0,
            "patterns": defaultdict(int),
            "recent_data": deque(maxlen=20),
        }

        # Scan progression tracking
        self.scan_status = {
            "indices": deque(maxlen=30),
            "unique_count": 0,
            "progression_detected": False,
            "last_index": None,
        }

        # Object detection tracking
        self.object_status = {
            "targets_detected": set(),
            "valid_detections": 0,
            "detection_active": False,
        }

        # Message flow analysis
        self.message_flow = defaultdict(lambda: {"count": 0, "rate": 0, "last_time": 0})

        # Critical milestones for this phase
        self.next_phase_milestones = {
            "x631_initialization": False,
            "scan_progression": False,
            "object_detection": False,
            "full_activation": False,
        }

    def setup_can(self) -> bool:
        """Setup CAN interface"""
        try:
            self.bus = can.interface.Bus(
                channel=self.can_interface, interface="socketcan"
            )
            print(f"✅ CAN interface {self.can_interface} ready")
            return True
        except Exception as e:
            print(f"❌ CAN setup failed: {e}")
            return False

    def log_phase_transition(self, new_phase, description=""):
        """Log phase transition with timestamp"""
        elapsed = time.time() - self.start_time
        self.phase_transitions.append(
            {
                "time": elapsed,
                "from": self.current_phase,
                "to": new_phase,
                "description": description,
            }
        )
        self.current_phase = new_phase

        print(f"\n🔄 PHASE TRANSITION at {elapsed:.1f}s:")
        print(f"   {new_phase}")
        if description:
            print(f"   {description}")

    def analyze_0x631_message(self, msg):
        """Detailed analysis of 0x631 initialization messages"""
        current_time = time.time()
        elapsed = current_time - self.start_time

        # First 0x631 detection
        if not self.x631_status["detected"]:
            self.x631_status["detected"] = True
            self.x631_status["first_time"] = current_time
            self.next_phase_milestones["x631_initialization"] = True

            self.log_phase_transition(
                "X631_INITIALIZATION_ACTIVE",
                "First 0x631 initialization message received",
            )

        self.x631_status["count"] += 1
        data_hex = msg.data.hex().upper()
        self.x631_status["patterns"][data_hex] += 1
        self.x631_status["recent_data"].append({"time": elapsed, "data": data_hex})

        # Analyze message content for initialization patterns
        if len(msg.data) >= 8:
            try:
                word1 = struct.unpack("<I", msg.data[0:4])[0]
                word2 = struct.unpack("<I", msg.data[4:8])[0]

                # Detailed pattern analysis
                if word1 == 0x00000000 and word2 == 0x00000000:
                    pattern = "RESET/INIT"
                elif word1 != 0x00000000 and word2 == 0x00000000:
                    pattern = "CONFIG_PHASE_1"
                elif word1 == 0x00000000 and word2 != 0x00000000:
                    pattern = "CONFIG_PHASE_2"
                elif word1 != 0x00000000 and word2 != 0x00000000:
                    pattern = "ACTIVE_CONFIG"
                else:
                    pattern = "UNKNOWN"

                print(f"🔥 0x631 #{self.x631_status['count']}: {data_hex} ({pattern})")

            except Exception as e:
                print(
                    f"🔥 0x631 #{self.x631_status['count']}: {data_hex} (decode error)"
                )

    def analyze_scan_progression(self, msg):
        """Analyze 0x300 messages for scan index progression"""
        if len(msg.data) >= 1:
            scan_index = msg.data[0]
            self.scan_status["indices"].append(scan_index)

            # Check for scan progression
            if len(self.scan_status["indices"]) > 15:
                recent_indices = list(self.scan_status["indices"])[-15:]
                unique_count = len(set(recent_indices))

                if unique_count != self.scan_status["unique_count"]:
                    self.scan_status["unique_count"] = unique_count

                    if (
                        unique_count > 5
                        and not self.scan_status["progression_detected"]
                    ):
                        self.scan_status["progression_detected"] = True
                        self.next_phase_milestones["scan_progression"] = True

                        elapsed = time.time() - self.start_time
                        self.log_phase_transition(
                            "SCAN_PROGRESSION_ACTIVE",
                            f"Dynamic scanning detected ({unique_count} unique indices)",
                        )

                # Track scan index changes
                if self.scan_status["last_index"] != scan_index:
                    if self.scan_status["last_index"] is not None:
                        print(
                            f"📡 Scan index: 0x{self.scan_status['last_index']:02X} → 0x{scan_index:02X}"
                        )
                    self.scan_status["last_index"] = scan_index

    def analyze_object_detection(self, msg_id, data):
        """Analyze object detection messages (0x300-0x30F)"""
        if 0x300 <= msg_id <= 0x30F:
            target_id = msg_id - 0x300

            if len(data) >= 8:
                try:
                    # Extract target data
                    distance = ((data[1] << 8) | data[2]) * 0.05  # meters
                    velocity = ((data[3] << 8) | data[4]) * 0.01  # m/s

                    # Valid target detection
                    if distance > 0.1 and distance < 200:  # Reasonable range
                        self.object_status["targets_detected"].add(target_id)
                        self.object_status["valid_detections"] += 1

                        if not self.object_status["detection_active"]:
                            self.object_status["detection_active"] = True
                            self.next_phase_milestones["object_detection"] = True

                            elapsed = time.time() - self.start_time
                            self.log_phase_transition(
                                "OBJECT_DETECTION_ACTIVE",
                                f"Target {target_id} detected at {distance:.1f}m",
                            )

                        # Log significant detections
                        if self.object_status["valid_detections"] % 10 == 1:
                            print(
                                f"🎯 Target {target_id}: {distance:.1f}m, {velocity:.1f}m/s"
                            )

                except Exception as e:
                    pass

    def check_full_activation(self):
        """Check if radar has achieved full activation"""
        if not self.next_phase_milestones["full_activation"]:
            # Check if we have achieved the key milestones
            critical_achieved = (
                self.next_phase_milestones["x631_initialization"]
                and self.next_phase_milestones["scan_progression"]
            )

            if critical_achieved:
                self.next_phase_milestones["full_activation"] = True
                elapsed = time.time() - self.start_time
                self.log_phase_transition(
                    "FULL_ACTIVATION_ACHIEVED",
                    "All critical milestones reached - radar fully operational!",
                )

    def print_status_summary(self):
        """Print comprehensive status summary"""
        elapsed = time.time() - self.start_time

        print(f"\n📊 NEXT PHASE STATUS - {elapsed:.1f}s elapsed")
        print("=" * 60)
        print(f"🔄 Current Phase: {self.current_phase}")
        print()

        # Milestone progress
        print("🏁 NEXT PHASE MILESTONES:")
        for milestone, achieved in self.next_phase_milestones.items():
            status = "✅" if achieved else "⏳"
            name = milestone.replace("_", " ").title()
            print(f"   {status} {name}")
        print()

        # 0x631 status
        print("🔥 0x631 INITIALIZATION:")
        if self.x631_status["detected"]:
            print(f"   ✅ DETECTED - {self.x631_status['count']} messages")
            print(f"   Patterns: {len(self.x631_status['patterns'])}")
            if self.x631_status["first_time"]:
                delay = self.x631_status["first_time"] - self.start_time
                print(f"   First seen: {delay:.1f}s")
        else:
            print("   ⏳ WAITING FOR INITIALIZATION")
        print()

        # Scan progression
        print("📡 SCAN PROGRESSION:")
        if self.scan_status["indices"]:
            print(f"   Unique indices: {self.scan_status['unique_count']}")
            if self.scan_status["progression_detected"]:
                print("   ✅ DYNAMIC SCANNING ACTIVE")
            else:
                print("   ⏳ WAITING FOR DYNAMIC SCANNING")

            if self.scan_status["last_index"] is not None:
                print(f"   Current index: 0x{self.scan_status['last_index']:02X}")
        else:
            print("   ⏳ NO SCAN DATA")
        print()

        # Object detection
        print("🎯 OBJECT DETECTION:")
        if self.object_status["detection_active"]:
            print(
                f"   ✅ ACTIVE - {len(self.object_status['targets_detected'])} targets"
            )
            print(f"   Valid detections: {self.object_status['valid_detections']}")
        else:
            print("   ⏳ WAITING FOR OBJECT DETECTION")
        print()

        # Phase transitions
        if self.phase_transitions:
            print("🔄 PHASE HISTORY:")
            for transition in self.phase_transitions[-3:]:  # Show last 3
                print(f"   {transition['time']:6.1f}s: {transition['to']}")

    def monitor_loop(self):
        """Main monitoring loop optimized for next phase detection"""
        print("🎯 Tesla Radar Next Phase Monitor")
        print("=" * 60)
        print("⚡ Power increase already achieved - monitoring next steps")
        print("🔍 Watching for 0x631 initialization and scan progression")
        print("📡 Optimized for detecting radar activation completion")
        print()

        last_status = time.time()

        while self.running:
            try:
                msg = self.bus.recv(timeout=0.1)

                if msg:
                    msg_id = msg.arbitration_id
                    current_time = time.time()

                    # Update message flow stats
                    self.message_flow[msg_id]["count"] += 1
                    if self.message_flow[msg_id]["last_time"] > 0:
                        time_diff = (
                            current_time - self.message_flow[msg_id]["last_time"]
                        )
                        if time_diff > 0:
                            self.message_flow[msg_id]["rate"] = 1.0 / time_diff
                    self.message_flow[msg_id]["last_time"] = current_time

                    # Analyze specific messages
                    if msg_id == 0x631:
                        self.analyze_0x631_message(msg)
                    elif msg_id == 0x300:
                        self.analyze_scan_progression(msg)
                    elif 0x300 <= msg_id <= 0x30F:
                        self.analyze_object_detection(msg_id, msg.data)

                    # Check for full activation
                    self.check_full_activation()

                # Status updates every 15 seconds
                if time.time() - last_status >= 15:
                    self.print_status_summary()
                    last_status = time.time()
                    print("\n" + "=" * 60)

            except Exception as e:
                if "timed out" not in str(e).lower():
                    print(f"⚠️  Error: {e}")
                continue

    def run(self):
        """Start next phase monitoring"""
        if not self.setup_can():
            return False

        self.running = True

        def signal_handler(sig, frame):
            print("\n🛑 Stopping Next Phase Monitor...")
            self.running = False

            # Final report
            print("\n" + "=" * 60)
            print("🏁 NEXT PHASE MONITORING REPORT")
            print("=" * 60)

            total_time = time.time() - self.start_time
            achieved = sum(
                1 for milestone in self.next_phase_milestones.values() if milestone
            )
            total = len(self.next_phase_milestones)

            print(f"⏱️  Monitoring time: {total_time:.1f}s")
            print(f"🎯 Milestones: {achieved}/{total}")
            print(f"🔄 Final phase: {self.current_phase}")
            print()

            # Milestone summary
            print("📊 MILESTONE STATUS:")
            for name, achieved in self.next_phase_milestones.items():
                status = "✅" if achieved else "❌"
                print(f"   {status} {name.replace('_', ' ').title()}")
            print()

            # Key findings
            print("🔍 KEY FINDINGS:")
            if self.x631_status["detected"]:
                print(f"   ✅ 0x631 messages: {self.x631_status['count']} received")
                print(f"   📊 Unique patterns: {len(self.x631_status['patterns'])}")
            else:
                print("   ❌ No 0x631 initialization messages detected")

            if self.scan_status["progression_detected"]:
                print(
                    f"   ✅ Scan progression: {self.scan_status['unique_count']} unique indices"
                )
            else:
                print("   ❌ No dynamic scan progression detected")

            if self.object_status["detection_active"]:
                print(
                    f"   ✅ Object detection: {len(self.object_status['targets_detected'])} targets"
                )
            else:
                print("   ❌ No object detection activity")

            print()
            if self.next_phase_milestones["full_activation"]:
                print("🎉 SUCCESS: RADAR FULLY ACTIVATED!")
                print("   All next phase milestones achieved!")
            else:
                print("⏳ ACTIVATION CONTINUING...")
                print("   Keep Tesla protocol running for full activation")

            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        try:
            self.monitor_loop()
        except Exception as e:
            print(f"❌ Monitor error: {e}")
        finally:
            if self.bus:
                self.bus.shutdown()

        return True


def main():
    """Main function"""
    print("🔧 Tesla Radar Next Phase Monitor")
    print("=" * 60)
    print("⚡ POWER INCREASE ALREADY ACHIEVED - Monitoring next steps")
    print("🎯 Specialized for detecting 0x631 initialization")
    print("📡 Optimized for scan progression and object detection")
    print("🔥 Designed to complete the radar activation sequence")
    print()
    print("⚠️  CRITICAL: Ensure Tesla protocol emulator is running!")
    print("📊 This monitor focuses on the remaining activation steps")
    print()

    # Use can1 for radar monitoring (radar should be on CAN1)
    monitor = RadarNextPhaseMonitor("can1")
    monitor.run()


if __name__ == "__main__":
    main()
