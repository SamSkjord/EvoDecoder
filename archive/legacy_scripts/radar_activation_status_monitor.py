#!/usr/bin/env python3
"""
Tesla Radar Activation Status Monitor
====================================

Real-time monitoring tool to track Tesla radar activation progress.
Provides comprehensive status updates on:
- Power state changes
- 0x631 initialization detection
- Scan index progression
- Object detection capability
- Full activation sequence tracking

This monitor provides detailed insights into the radar activation process
and helps identify exactly where we are in the sequence.
"""

import can
import time
import signal
import sys
import struct
from collections import defaultdict, deque
from datetime import datetime
import threading


class RadarActivationStatusMonitor:
    """Comprehensive Tesla radar activation status monitor"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None
        self.running = False
        self.start_time = time.time()

        # Activation tracking
        self.activation_milestones = {
            "protocol_detected": False,
            "power_increase": False,
            "x631_initialization": False,
            "scan_progression": False,
            "object_detection": False,
            "full_activation": False,
        }

        # Message tracking
        self.message_counts = defaultdict(int)
        self.x631_messages = []
        self.x631_first_time = None
        self.x631_patterns = defaultdict(int)

        # Radar state tracking
        self.scan_indices = deque(maxlen=50)
        self.power_levels = deque(maxlen=50)
        self.target_data = defaultdict(list)

        # Tesla protocol detection
        self.tesla_messages_detected = set()
        self.protocol_start_time = None

        # Status display
        self.last_status_time = 0
        self.status_interval = 10  # seconds

    def setup_can(self) -> bool:
        """Setup CAN interface"""
        try:
            self.bus = can.interface.Bus(
                channel=self.can_interface, bustype="socketcan"
            )
            print(f"✅ CAN interface {self.can_interface} setup successful")
            return True
        except Exception as e:
            print(f"❌ CAN interface setup failed: {e}")
            return False

    def analyze_tesla_protocol_message(self, msg_id, data):
        """Analyze Tesla protocol messages to detect activation"""
        tesla_msg_ids = {
            0x199,
            0x169,
            0x119,
            0x109,
            0x2B9,
            0x2A9,
            0x2D9,
            0x159,
            0x149,
            0x129,
            0x1A9,
            0x209,
            0x219,
        }

        if msg_id in tesla_msg_ids:
            if msg_id not in self.tesla_messages_detected:
                self.tesla_messages_detected.add(msg_id)
                elapsed = time.time() - self.start_time
                print(f"📡 Tesla message 0x{msg_id:03X} detected at {elapsed:.1f}s")

                # Check if we have enough Tesla messages to consider protocol active
                if (
                    len(self.tesla_messages_detected) >= 4
                    and not self.activation_milestones["protocol_detected"]
                ):
                    self.activation_milestones["protocol_detected"] = True
                    self.protocol_start_time = time.time()
                    print(
                        f"🚗 TESLA PROTOCOL DETECTED! ({len(self.tesla_messages_detected)} message types)"
                    )

    def analyze_0x631_message(self, msg):
        """Analyze 0x631 initialization messages"""
        current_time = time.time()
        elapsed = current_time - self.start_time

        if self.x631_first_time is None:
            self.x631_first_time = current_time
            print(f"\n🎉 FIRST 0x631 INITIALIZATION MESSAGE!")
            print(f"   Time: {elapsed:.1f}s after monitoring start")
            if self.protocol_start_time:
                protocol_elapsed = current_time - self.protocol_start_time
                print(
                    f"   Protocol delay: {protocol_elapsed:.1f}s after Tesla protocol"
                )
            self.activation_milestones["x631_initialization"] = True

        data_hex = msg.data.hex().upper()
        self.x631_patterns[data_hex] += 1
        self.x631_messages.append(
            {"time": current_time, "data": data_hex, "elapsed": elapsed}
        )

        # Analyze message content
        if len(msg.data) >= 8:
            try:
                word1 = struct.unpack("<I", msg.data[0:4])[0]
                word2 = struct.unpack("<I", msg.data[4:8])[0]

                # Look for initialization patterns
                if word1 == 0x00000000 and word2 == 0x00000000:
                    pattern_type = "RESET/INIT"
                elif word1 != 0x00000000 or word2 != 0x00000000:
                    pattern_type = "CONFIG/STATUS"
                else:
                    pattern_type = "UNKNOWN"

                print(f"   Data: {data_hex} ({pattern_type})")

            except Exception as e:
                print(f"   Data: {data_hex} (decode error)")

    def analyze_radar_status(self, msg):
        """Analyze 0x300 radar status for power and scanning"""
        if len(msg.data) >= 3:
            try:
                scan_index = msg.data[0] if len(msg.data) > 0 else 0
                power_indicator = msg.data[2] if len(msg.data) > 2 else 0

                self.scan_indices.append(scan_index)
                self.power_levels.append(power_indicator)

                # Check for power increase
                if len(self.power_levels) > 5:
                    recent_power = list(self.power_levels)[-5:]
                    max_recent = max(recent_power)
                    min_recent = min(recent_power)

                    if (
                        max_recent > min_recent
                        and not self.activation_milestones["power_increase"]
                    ):
                        elapsed = time.time() - self.start_time
                        print(f"⚡ POWER INCREASE DETECTED at {elapsed:.1f}s!")
                        print(f"   Power range: {min_recent} → {max_recent}")
                        self.activation_milestones["power_increase"] = True

                # Check for scan progression
                if len(self.scan_indices) > 10:
                    recent_scans = list(self.scan_indices)[-10:]
                    unique_scans = len(set(recent_scans))

                    if (
                        unique_scans > 3
                        and not self.activation_milestones["scan_progression"]
                    ):
                        elapsed = time.time() - self.start_time
                        print(f"📡 SCAN PROGRESSION DETECTED at {elapsed:.1f}s!")
                        print(f"   Unique scan indices: {unique_scans}")
                        self.activation_milestones["scan_progression"] = True

            except Exception as e:
                pass

    def analyze_object_detection(self, msg_id, data):
        """Analyze object detection messages (0x300-0x30F range)"""
        if 0x300 <= msg_id <= 0x30F:
            target_id = msg_id - 0x300

            if len(data) >= 8:
                try:
                    # Basic target data extraction
                    distance = ((data[1] << 8) | data[2]) * 0.05  # meters
                    velocity = ((data[3] << 8) | data[4]) * 0.01  # m/s

                    if distance > 0.1:  # Valid distance reading
                        self.target_data[target_id].append(
                            {
                                "time": time.time(),
                                "distance": distance,
                                "velocity": velocity,
                            }
                        )

                        # Keep only recent data
                        if len(self.target_data[target_id]) > 20:
                            self.target_data[target_id] = self.target_data[target_id][
                                -20:
                            ]

                        # Check for object detection capability
                        if not self.activation_milestones["object_detection"]:
                            active_targets = len(
                                [
                                    tid
                                    for tid, data in self.target_data.items()
                                    if len(data) > 3
                                ]
                            )
                            if active_targets > 0:
                                elapsed = time.time() - self.start_time
                                print(
                                    f"🎯 OBJECT DETECTION CAPABILITY at {elapsed:.1f}s!"
                                )
                                print(f"   Active targets: {active_targets}")
                                self.activation_milestones["object_detection"] = True

                except Exception as e:
                    pass

    def check_full_activation(self):
        """Check if radar is fully activated"""
        if not self.activation_milestones["full_activation"]:
            required_milestones = [
                "protocol_detected",
                "x631_initialization",
                "scan_progression",
            ]
            achieved = sum(
                1
                for milestone in required_milestones
                if self.activation_milestones[milestone]
            )

            if achieved >= len(required_milestones):
                elapsed = time.time() - self.start_time
                print(f"\n🎉 FULL RADAR ACTIVATION ACHIEVED at {elapsed:.1f}s!")
                print("   All critical milestones reached!")
                self.activation_milestones["full_activation"] = True

    def print_comprehensive_status(self):
        """Print comprehensive status update"""
        elapsed = time.time() - self.start_time

        print(f"\n📊 COMPREHENSIVE STATUS - {elapsed:.1f}s elapsed")
        print("=" * 60)

        # Activation milestones
        print("🏁 ACTIVATION MILESTONES:")
        for milestone, achieved in self.activation_milestones.items():
            status = "✅" if achieved else "⏳"
            milestone_name = milestone.replace("_", " ").title()
            print(f"   {status} {milestone_name}")

        # Tesla protocol status
        print(f"\n🚗 TESLA PROTOCOL:")
        print(f"   Message types detected: {len(self.tesla_messages_detected)}")
        if self.tesla_messages_detected:
            print(
                f"   Active messages: {', '.join(f'0x{mid:03X}' for mid in sorted(self.tesla_messages_detected))}"
            )

        # 0x631 status
        print(f"\n🔥 0x631 INITIALIZATION:")
        if self.x631_messages:
            print(f"   Messages received: {len(self.x631_messages)}")
            print(f"   Unique patterns: {len(self.x631_patterns)}")
            if self.x631_first_time:
                init_delay = self.x631_first_time - self.start_time
                print(f"   First detected: {init_delay:.1f}s after start")
        else:
            print("   Status: NOT DETECTED")

        # Radar scanning status
        if self.scan_indices:
            unique_scans = len(set(self.scan_indices))
            print(f"\n📡 RADAR SCANNING:")
            print(f"   Unique scan indices: {unique_scans}")
            if unique_scans > 1:
                print("   Status: ✅ DYNAMIC SCANNING")
            else:
                print("   Status: ❌ STATIC SCANNING")

        # Object detection status
        active_targets = len(
            [tid for tid, data in self.target_data.items() if len(data) > 3]
        )
        print(f"\n🎯 OBJECT DETECTION:")
        print(f"   Active targets: {active_targets}")
        if active_targets > 0:
            print("   Status: ✅ DETECTING OBJECTS")
        else:
            print("   Status: ⏳ WAITING FOR OBJECTS")

        # Overall assessment
        achieved_count = sum(
            1 for achieved in self.activation_milestones.values() if achieved
        )
        total_milestones = len(self.activation_milestones)
        progress_percent = (achieved_count / total_milestones) * 100

        print(
            f"\n🎯 OVERALL PROGRESS: {achieved_count}/{total_milestones} ({progress_percent:.0f}%)"
        )

        if self.activation_milestones["full_activation"]:
            print("🎉 RADAR FULLY ACTIVATED AND OPERATIONAL!")
        elif achieved_count >= 3:
            print("🔥 RADAR ACTIVATION IN PROGRESS - EXCELLENT PROGRESS!")
        elif achieved_count >= 1:
            print("⚡ RADAR RESPONDING - GOOD PROGRESS!")
        else:
            print("⏳ WAITING FOR RADAR RESPONSE...")

    def monitor_loop(self):
        """Main monitoring loop"""
        print("🎯 Tesla Radar Activation Status Monitor")
        print("=" * 60)
        print("📡 Comprehensive radar activation tracking")
        print("🔍 Monitoring all phases of radar startup sequence")
        print("⚡ Real-time milestone detection and progress tracking")
        print()

        while self.running:
            try:
                # Non-blocking message check
                msg = self.bus.recv(timeout=0.1)

                if msg:
                    msg_id = msg.arbitration_id
                    self.message_counts[msg_id] += 1

                    # Analyze different message types
                    if msg_id == 0x631:
                        self.analyze_0x631_message(msg)
                    elif msg_id == 0x300:
                        self.analyze_radar_status(msg)
                    elif 0x300 <= msg_id <= 0x30F:
                        self.analyze_object_detection(msg_id, msg.data)
                    else:
                        # Check for Tesla protocol messages
                        self.analyze_tesla_protocol_message(msg_id, msg.data)

                    # Check for full activation
                    self.check_full_activation()

                # Periodic status updates
                current_time = time.time()
                if current_time - self.last_status_time >= self.status_interval:
                    self.print_comprehensive_status()
                    self.last_status_time = current_time
                    print("\n" + "=" * 60)

            except Exception as e:
                if "timed out" not in str(e).lower():
                    print(f"⚠️  Monitor error: {e}")
                continue

    def run(self):
        """Start the activation status monitor"""
        if not self.setup_can():
            return False

        self.running = True

        def signal_handler(sig, frame):
            print("\n🛑 Stopping Radar Activation Status Monitor...")
            self.running = False

            # Final comprehensive report
            print("\n" + "=" * 60)
            print("🏁 FINAL ACTIVATION REPORT")
            print("=" * 60)
            self.print_comprehensive_status()

            # Summary of achievements
            achieved = [
                name for name, status in self.activation_milestones.items() if status
            ]
            print(
                f"\n🎯 ACHIEVEMENTS: {len(achieved)}/{len(self.activation_milestones)}"
            )
            for achievement in achieved:
                print(f"   ✅ {achievement.replace('_', ' ').title()}")

            if self.activation_milestones["full_activation"]:
                print(f"\n🎉 RADAR FULLY ACTIVATED!")
                print(f"   Total time: {time.time() - self.start_time:.1f}s")
            else:
                print(f"\n⏳ ACTIVATION IN PROGRESS")
                print(f"   Continue monitoring for full activation")

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
    print("🔧 Tesla Radar Activation Status Monitor")
    print("=" * 60)
    print("🎯 Comprehensive radar activation progress tracking")
    print("📡 Monitors all phases of Tesla radar startup sequence")
    print("⚡ Real-time milestone detection and status updates")
    print("🔥 Designed to track progression from power-up to full operation")
    print()
    print("⚠️  Ensure Tesla protocol emulator is running!")
    print("📊 This monitor will track activation progress in real-time")
    print()

    monitor = RadarActivationStatusMonitor("can1")
    monitor.run()


if __name__ == "__main__":
    main()
