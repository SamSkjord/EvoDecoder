#!/usr/bin/env python3
"""
Tesla Radar Activation Dashboard
===============================

Real-time dashboard for monitoring Tesla radar activation progress.
Provides a comprehensive view of:
- Activation milestone progress
- Message flow analysis
- Power state tracking
- 0x631 initialization sequence
- Scan index progression
- Object detection status

This dashboard is designed to run alongside your Tesla protocol emulator
and provide real-time insights into the radar activation process.
"""

import can
import time
import signal
import sys
import struct
import os
from collections import defaultdict, deque
from datetime import datetime


class RadarActivationDashboard:
    """Real-time Tesla radar activation dashboard"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None
        self.running = False
        self.start_time = time.time()

        # Activation milestones with timestamps
        self.milestones = {
            "tesla_protocol_active": {"achieved": False, "time": None},
            "power_increase_detected": {"achieved": False, "time": None},
            "x631_initialization": {"achieved": False, "time": None},
            "scan_progression": {"achieved": False, "time": None},
            "object_detection": {"achieved": False, "time": None},
            "full_activation": {"achieved": False, "time": None},
        }

        # Message tracking
        self.message_stats = defaultdict(
            lambda: {"count": 0, "last_seen": 0, "rate": 0}
        )
        self.tesla_messages = {
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

        # 0x631 tracking
        self.x631_data = {
            "count": 0,
            "first_time": None,
            "patterns": defaultdict(int),
            "recent_messages": deque(maxlen=10),
        }

        # Radar state tracking
        self.radar_state = {
            "scan_indices": deque(maxlen=20),
            "power_levels": deque(maxlen=20),
            "target_count": 0,
            "active_targets": set(),
        }

        # Display settings
        self.display_interval = 5  # seconds
        self.last_display = 0

    def setup_can(self) -> bool:
        """Setup CAN interface"""
        try:
            self.bus = can.interface.Bus(
                channel=self.can_interface, bustype="socketcan"
            )
            return True
        except Exception as e:
            print(f"❌ CAN setup failed: {e}")
            return False

    def clear_screen(self):
        """Clear terminal screen"""
        os.system("clear" if os.name == "posix" else "cls")

    def update_milestone(self, milestone_name, description=""):
        """Update milestone status with timestamp"""
        if not self.milestones[milestone_name]["achieved"]:
            self.milestones[milestone_name]["achieved"] = True
            self.milestones[milestone_name]["time"] = time.time()
            elapsed = time.time() - self.start_time
            print(
                f"🎉 MILESTONE: {milestone_name.replace('_', ' ').upper()} at {elapsed:.1f}s"
            )
            if description:
                print(f"   {description}")

    def analyze_message(self, msg):
        """Analyze incoming CAN message"""
        msg_id = msg.arbitration_id
        current_time = time.time()

        # Update message statistics
        self.message_stats[msg_id]["count"] += 1
        self.message_stats[msg_id]["last_seen"] = current_time

        # Calculate message rate (messages per second)
        if self.message_stats[msg_id]["count"] > 1:
            time_diff = current_time - (self.message_stats[msg_id]["last_seen"] - 1)
            if time_diff > 0:
                self.message_stats[msg_id]["rate"] = 1.0 / time_diff

        # Check Tesla protocol messages
        if msg_id in self.tesla_messages:
            tesla_active_count = sum(
                1 for tid in self.tesla_messages if self.message_stats[tid]["count"] > 0
            )
            if (
                tesla_active_count >= 4
                and not self.milestones["tesla_protocol_active"]["achieved"]
            ):
                self.update_milestone(
                    "tesla_protocol_active",
                    f"{tesla_active_count} Tesla message types active",
                )

        # Analyze specific message types
        if msg_id == 0x631:
            self.analyze_0x631(msg)
        elif msg_id == 0x300:
            self.analyze_radar_status(msg)
        elif 0x300 <= msg_id <= 0x30F:
            self.analyze_target_data(msg_id, msg.data)

    def analyze_0x631(self, msg):
        """Analyze 0x631 initialization messages"""
        self.x631_data["count"] += 1

        if self.x631_data["first_time"] is None:
            self.x631_data["first_time"] = time.time()
            self.update_milestone("x631_initialization", "First 0x631 message received")

        data_hex = msg.data.hex().upper()
        self.x631_data["patterns"][data_hex] += 1
        self.x631_data["recent_messages"].append(
            {"time": time.time(), "data": data_hex}
        )

    def analyze_radar_status(self, msg):
        """Analyze 0x300 radar status messages"""
        if len(msg.data) >= 3:
            scan_index = msg.data[0]
            power_level = msg.data[2]

            self.radar_state["scan_indices"].append(scan_index)
            self.radar_state["power_levels"].append(power_level)

            # Check for power increase
            if len(self.radar_state["power_levels"]) > 5:
                recent_power = list(self.radar_state["power_levels"])[-5:]
                if max(recent_power) > min(recent_power):
                    if not self.milestones["power_increase_detected"]["achieved"]:
                        self.update_milestone(
                            "power_increase_detected",
                            f"Power: {min(recent_power)} → {max(recent_power)}",
                        )

            # Check for scan progression
            if len(self.radar_state["scan_indices"]) > 10:
                recent_scans = list(self.radar_state["scan_indices"])[-10:]
                unique_scans = len(set(recent_scans))
                if unique_scans > 3:
                    if not self.milestones["scan_progression"]["achieved"]:
                        self.update_milestone(
                            "scan_progression", f"{unique_scans} unique scan indices"
                        )

    def analyze_target_data(self, msg_id, data):
        """Analyze target detection messages"""
        target_id = msg_id - 0x300

        if len(data) >= 8:
            try:
                distance = ((data[1] << 8) | data[2]) * 0.05
                if distance > 0.1:  # Valid target
                    self.radar_state["active_targets"].add(target_id)

                    if len(self.radar_state["active_targets"]) > 0:
                        if not self.milestones["object_detection"]["achieved"]:
                            self.update_milestone(
                                "object_detection",
                                f"{len(self.radar_state['active_targets'])} active targets",
                            )
            except:
                pass

    def check_full_activation(self):
        """Check if all critical milestones are achieved"""
        critical_milestones = [
            "tesla_protocol_active",
            "x631_initialization",
            "scan_progression",
        ]
        achieved = sum(1 for m in critical_milestones if self.milestones[m]["achieved"])

        if (
            achieved >= len(critical_milestones)
            and not self.milestones["full_activation"]["achieved"]
        ):
            self.update_milestone(
                "full_activation", "All critical milestones achieved!"
            )

    def display_dashboard(self):
        """Display the real-time dashboard"""
        self.clear_screen()

        elapsed = time.time() - self.start_time

        print("🎯 TESLA RADAR ACTIVATION DASHBOARD")
        print("=" * 70)
        print(
            f"⏱️  Runtime: {elapsed:.1f}s | Interface: {self.can_interface} | {datetime.now().strftime('%H:%M:%S')}"
        )
        print()

        # Activation Progress Bar
        achieved_count = sum(1 for m in self.milestones.values() if m["achieved"])
        total_milestones = len(self.milestones)
        progress = achieved_count / total_milestones
        bar_length = 30
        filled_length = int(bar_length * progress)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)

        print(
            f"🏁 ACTIVATION PROGRESS: [{bar}] {achieved_count}/{total_milestones} ({progress*100:.0f}%)"
        )
        print()

        # Milestone Status
        print("📊 ACTIVATION MILESTONES:")
        for milestone_name, milestone_data in self.milestones.items():
            status = "✅" if milestone_data["achieved"] else "⏳"
            name = milestone_name.replace("_", " ").title()

            if milestone_data["achieved"] and milestone_data["time"]:
                milestone_time = milestone_data["time"] - self.start_time
                print(f"   {status} {name:<25} ({milestone_time:.1f}s)")
            else:
                print(f"   {status} {name}")
        print()

        # Tesla Protocol Status
        tesla_active = sum(
            1 for tid in self.tesla_messages if self.message_stats[tid]["count"] > 0
        )
        print(
            f"🚗 TESLA PROTOCOL: {tesla_active}/{len(self.tesla_messages)} message types active"
        )
        if tesla_active > 0:
            active_msgs = [
                f"0x{tid:03X}"
                for tid in self.tesla_messages
                if self.message_stats[tid]["count"] > 0
            ]
            print(f"   Active: {', '.join(active_msgs[:8])}")  # Show first 8
        print()

        # 0x631 Status
        print(f"🔥 0x631 INITIALIZATION:")
        if self.x631_data["count"] > 0:
            print(f"   Messages: {self.x631_data['count']}")
            print(f"   Patterns: {len(self.x631_data['patterns'])}")
            if self.x631_data["first_time"]:
                init_delay = self.x631_data["first_time"] - self.start_time
                print(f"   First seen: {init_delay:.1f}s")
        else:
            print("   Status: ⏳ WAITING FOR INITIALIZATION")
        print()

        # Radar State
        print(f"📡 RADAR STATE:")
        if self.radar_state["scan_indices"]:
            unique_scans = len(set(self.radar_state["scan_indices"]))
            current_scan = (
                list(self.radar_state["scan_indices"])[-1]
                if self.radar_state["scan_indices"]
                else 0
            )
            print(f"   Scan Index: 0x{current_scan:02X} ({unique_scans} unique values)")

            if unique_scans > 1:
                print("   Scanning: ✅ DYNAMIC")
            else:
                print("   Scanning: ❌ STATIC")
        else:
            print("   Scanning: ⏳ NO DATA")

        if self.radar_state["power_levels"]:
            current_power = (
                list(self.radar_state["power_levels"])[-1]
                if self.radar_state["power_levels"]
                else 0
            )
            max_power = (
                max(self.radar_state["power_levels"])
                if self.radar_state["power_levels"]
                else 0
            )
            print(f"   Power: Current={current_power}, Max={max_power}")
        print()

        # Object Detection
        print(f"🎯 OBJECT DETECTION:")
        print(f"   Active targets: {len(self.radar_state['active_targets'])}")
        if self.radar_state["active_targets"]:
            target_list = ", ".join(
                f"T{tid}" for tid in sorted(self.radar_state["active_targets"])
            )
            print(f"   Targets: {target_list}")
        print()

        # Message Activity (Top 10)
        print("📨 MESSAGE ACTIVITY (Top 10):")
        sorted_messages = sorted(
            self.message_stats.items(), key=lambda x: x[1]["count"], reverse=True
        )[:10]
        for msg_id, stats in sorted_messages:
            rate_str = f"{stats['rate']:.1f}Hz" if stats["rate"] > 0 else "---"
            print(f"   0x{msg_id:03X}: {stats['count']:4d} messages ({rate_str})")

        # Status indicators
        print()
        if self.milestones["full_activation"]["achieved"]:
            print("🎉 STATUS: RADAR FULLY ACTIVATED AND OPERATIONAL!")
        elif achieved_count >= 3:
            print("🔥 STATUS: RADAR ACTIVATION IN PROGRESS - EXCELLENT!")
        elif achieved_count >= 1:
            print("⚡ STATUS: RADAR RESPONDING - GOOD PROGRESS!")
        else:
            print("⏳ STATUS: WAITING FOR RADAR RESPONSE...")

        print("\n" + "=" * 70)
        print("Press Ctrl+C to stop monitoring")

    def monitor_loop(self):
        """Main monitoring and display loop"""
        print("🎯 Starting Tesla Radar Activation Dashboard...")
        print("📡 Monitoring CAN bus for radar activation progress...")
        print()

        while self.running:
            try:
                # Check for messages
                msg = self.bus.recv(timeout=0.1)

                if msg:
                    self.analyze_message(msg)
                    self.check_full_activation()

                # Update display periodically
                current_time = time.time()
                if current_time - self.last_display >= self.display_interval:
                    self.display_dashboard()
                    self.last_display = current_time

            except Exception as e:
                if "timed out" not in str(e).lower():
                    continue

    def run(self):
        """Start the dashboard"""
        if not self.setup_can():
            return False

        self.running = True

        def signal_handler(sig, frame):
            print("\n🛑 Stopping Dashboard...")
            self.running = False

            # Final report
            self.clear_screen()
            print("🏁 FINAL RADAR ACTIVATION REPORT")
            print("=" * 70)

            total_time = time.time() - self.start_time
            achieved = sum(1 for m in self.milestones.values() if m["achieved"])
            total = len(self.milestones)

            print(f"⏱️  Total monitoring time: {total_time:.1f}s")
            print(
                f"🎯 Milestones achieved: {achieved}/{total} ({achieved/total*100:.0f}%)"
            )
            print()

            print("📊 MILESTONE TIMELINE:")
            for name, data in self.milestones.items():
                status = "✅" if data["achieved"] else "❌"
                milestone_name = name.replace("_", " ").title()
                if data["achieved"] and data["time"]:
                    milestone_time = data["time"] - self.start_time
                    print(f"   {status} {milestone_name:<25} ({milestone_time:.1f}s)")
                else:
                    print(f"   {status} {milestone_name}")

            print()
            if self.milestones["full_activation"]["achieved"]:
                print("🎉 SUCCESS: TESLA RADAR FULLY ACTIVATED!")
                print("   The radar is now operational and ready for object detection.")
            else:
                print("⏳ ACTIVATION IN PROGRESS")
                print("   Continue running Tesla protocol for full activation.")

            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        try:
            self.monitor_loop()
        except Exception as e:
            print(f"❌ Dashboard error: {e}")
        finally:
            if self.bus:
                self.bus.shutdown()

        return True


def main():
    """Main function"""
    print("🔧 Tesla Radar Activation Dashboard")
    print("=" * 70)
    print("🎯 Real-time radar activation progress monitoring")
    print("📡 Comprehensive milestone tracking and status display")
    print("⚡ Designed to run alongside Tesla protocol emulator")
    print()
    print("⚠️  IMPORTANT: Ensure Tesla protocol emulator is running!")
    print("📊 Dashboard will update every 5 seconds with current status")
    print()

    # Check if this should run on can0 or can1
    interface = "can1"  # Default to can1 for radar monitoring

    dashboard = RadarActivationDashboard(interface)
    dashboard.run()


if __name__ == "__main__":
    main()
