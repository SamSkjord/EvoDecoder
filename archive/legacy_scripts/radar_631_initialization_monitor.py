#!/usr/bin/env python3
"""
Tesla Radar 0x631 Initialization Monitor
========================================

Enhanced monitoring tool specifically designed to detect and analyze the critical
0x631 initialization messages that indicate full radar startup and activation.

This monitor focuses on:
- Detecting 0x631 initialization sequence
- Analyzing radar startup patterns
- Monitoring power state transitions
- Tracking scan index progression
- Identifying full activation markers

Usage:
    python3 radar_631_initialization_monitor.py

Run this alongside tesla_complete_emulator.py to monitor for full radar activation.
"""

import can
import time
import signal
import sys
from collections import defaultdict, deque
from datetime import datetime
import struct


class Radar631InitializationMonitor:
    """Enhanced monitor for Tesla radar 0x631 initialization sequence"""

    def __init__(self, can_interface: str = "can0"):
        self.can_interface = can_interface
        self.bus = None
        self.running = False
        self.start_time = time.time()

        # 0x631 specific tracking
        self.x631_messages = []
        self.x631_first_seen = None
        self.x631_count = 0
        self.x631_patterns = defaultdict(int)

        # Radar state tracking
        self.radar_states = deque(maxlen=100)
        self.power_levels = deque(maxlen=100)
        self.scan_indices = deque(maxlen=100)
        self.error_codes = set()

        # Message frequency tracking
        self.message_counts = defaultdict(int)
        self.message_timestamps = defaultdict(list)

        # Initialization sequence tracking
        self.initialization_phases = {
            "power_on": False,
            "vin_received": False,
            "config_sent": False,
            "x631_detected": False,
            "scanning_active": False,
            "fully_operational": False,
        }

        # Critical message tracking
        self.critical_messages = {
            0x631: {"count": 0, "last_seen": None, "data_patterns": []},
            0x300: {"count": 0, "last_seen": None, "power_levels": []},
            0x301: {"count": 0, "last_seen": None},
            0x302: {"count": 0, "last_seen": None},
            0x303: {"count": 0, "last_seen": None},
        }

    def setup_can(self) -> bool:
        """Setup CAN interface for monitoring"""
        try:
            self.bus = can.interface.Bus(
                channel=self.can_interface, interface="socketcan"
            )
            print(f"✅ CAN interface {self.can_interface} setup successful")
            return True
        except Exception as e:
            print(f"❌ CAN interface setup failed: {e}")
            return False

    def analyze_0x631_message(self, msg):
        """Detailed analysis of 0x631 initialization messages"""
        current_time = time.time()
        elapsed = current_time - self.start_time

        if self.x631_first_seen is None:
            self.x631_first_seen = current_time
            print(f"\n🎉 FIRST 0x631 INITIALIZATION MESSAGE DETECTED!")
            print(f"   Time: {elapsed:.1f}s after monitor start")
            print(f"   Timestamp: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
            self.initialization_phases["x631_detected"] = True

        self.x631_count += 1
        data_hex = msg.data.hex().upper()
        self.x631_patterns[data_hex] += 1

        # Store message for pattern analysis
        self.x631_messages.append(
            {
                "timestamp": current_time,
                "elapsed": elapsed,
                "data": msg.data,
                "hex": data_hex,
            }
        )

        # Update critical message tracking
        self.critical_messages[0x631]["count"] += 1
        self.critical_messages[0x631]["last_seen"] = current_time
        self.critical_messages[0x631]["data_patterns"].append(data_hex)

        print(f"🔥 0x631 #{self.x631_count} at {elapsed:.1f}s: {data_hex}")

        # Analyze data content
        if len(msg.data) >= 8:
            try:
                # Try to decode potential initialization data
                word1 = struct.unpack("<I", msg.data[0:4])[0]
                word2 = struct.unpack("<I", msg.data[4:8])[0]
                print(f"   Data analysis: Word1=0x{word1:08X}, Word2=0x{word2:08X}")

                # Look for specific initialization patterns
                if word1 == 0x00000000 and word2 == 0x00000000:
                    print("   🔍 Pattern: All zeros - possible reset/init")
                elif word1 != 0x00000000 or word2 != 0x00000000:
                    print("   🔍 Pattern: Non-zero data - possible config/status")

            except Exception as e:
                print(f"   ⚠️  Data decode error: {e}")

    def analyze_radar_status(self, msg):
        """Analyze 0x300 radar status messages for state changes"""
        if len(msg.data) >= 8:
            try:
                # Extract radar status information
                radar_state = msg.data[0] & 0x0F
                num_objects = (msg.data[0] >> 4) & 0x0F
                power_level = msg.data[2] if len(msg.data) > 2 else 0
                scan_index = msg.data[1] if len(msg.data) > 1 else 0

                # Track state changes
                self.radar_states.append(radar_state)
                self.power_levels.append(power_level)
                self.scan_indices.append(scan_index)

                # Update critical message tracking
                self.critical_messages[0x300]["count"] += 1
                self.critical_messages[0x300]["last_seen"] = time.time()
                self.critical_messages[0x300]["power_levels"].append(power_level)

                # Detect significant state changes
                if len(self.power_levels) > 1:
                    prev_power = self.power_levels[-2]
                    if power_level > prev_power:
                        elapsed = time.time() - self.start_time
                        print(
                            f"⚡ POWER INCREASE: {prev_power} → {power_level} at {elapsed:.1f}s"
                        )
                        if (
                            power_level > 0
                            and not self.initialization_phases["power_on"]
                        ):
                            self.initialization_phases["power_on"] = True
                            print("   🔋 Radar power-on phase detected!")

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
                        print(f"   Scan indices varying: {set(recent_indices)}")

            except Exception as e:
                print(f"⚠️  Error analyzing 0x300: {e}")

    def check_initialization_completion(self):
        """Check if radar has completed full initialization"""
        phases = self.initialization_phases

        if (
            phases["power_on"]
            and phases["x631_detected"]
            and phases["scanning_active"]
            and not phases["fully_operational"]
        ):

            phases["fully_operational"] = True
            elapsed = time.time() - self.start_time
            print(f"\n🎯 RADAR FULLY OPERATIONAL at {elapsed:.1f}s!")
            print("   ✅ Power activated")
            print("   ✅ 0x631 initialization detected")
            print("   ✅ Active scanning confirmed")
            print("   🚀 Radar is now ready for object detection!")

    def print_status_update(self):
        """Print comprehensive status update"""
        elapsed = time.time() - self.start_time

        print(f"\n📊 INITIALIZATION STATUS - {elapsed:.1f}s elapsed")
        print("=" * 60)

        # 0x631 status
        if self.x631_count > 0:
            time_since_first = elapsed - (self.x631_first_seen - self.start_time)
            print(f"🔥 0x631 MESSAGES: {self.x631_count} detected")
            print(f"   First seen: {time_since_first:.1f}s ago")
            print(f"   Unique patterns: {len(self.x631_patterns)}")

            # Show most common patterns
            if self.x631_patterns:
                sorted_patterns = sorted(
                    self.x631_patterns.items(), key=lambda x: x[1], reverse=True
                )
                print("   Top patterns:")
                for pattern, count in sorted_patterns[:3]:
                    print(f"     {pattern}: {count} times")
        else:
            print("❌ 0x631 INITIALIZATION: NOT DETECTED")

        # Radar state analysis
        if self.power_levels:
            current_power = self.power_levels[-1]
            max_power = max(self.power_levels)
            print(f"⚡ POWER LEVEL: {current_power} (max: {max_power})")

        if self.scan_indices:
            recent_indices = list(self.scan_indices)[-20:]
            unique_recent = len(set(recent_indices))
            print(
                f"📡 SCAN ACTIVITY: {unique_recent} unique indices in last 20 messages"
            )
            if unique_recent > 5:
                print("   ✅ Active scanning detected")
            else:
                print("   ⚠️  Limited scan activity")

        # Initialization phases
        print("🔄 INITIALIZATION PHASES:")
        for phase, status in self.initialization_phases.items():
            status_icon = "✅" if status else "⏳"
            print(f"   {status_icon} {phase.replace('_', ' ').title()}")

        # Message frequency analysis
        active_messages = len(
            [msg_id for msg_id, count in self.message_counts.items() if count > 0]
        )
        print(f"📈 ACTIVE CAN IDs: {active_messages}")

        # Top message frequencies
        if self.message_counts:
            sorted_msgs = sorted(
                self.message_counts.items(), key=lambda x: x[1], reverse=True
            )
            print("   Top active messages:")
            for msg_id, count in sorted_msgs[:5]:
                print(f"     0x{msg_id:03X}: {count} messages")

    def run(self):
        """Main monitoring loop"""
        if not self.setup_can():
            return False

        self.running = True

        def signal_handler(sig, frame):
            print("\n🛑 Stopping 0x631 Initialization Monitor...")
            self.running = False
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        print("🔍 Tesla Radar 0x631 Initialization Monitor")
        print("=" * 50)
        print("🎯 Monitoring for radar initialization sequence")
        print("🔥 Specifically watching for 0x631 messages")
        print("⚡ Tracking power state and scan activity")
        print("📡 Run alongside tesla_complete_emulator.py")
        print()

        last_status_update = 0
        message_count = 0

        try:
            while self.running:
                msg = self.bus.recv(timeout=0.1)
                if msg is not None:
                    message_count += 1
                    current_time = time.time()
                    msg_id = msg.arbitration_id

                    # Update message counts
                    self.message_counts[msg_id] += 1

                    # Critical message analysis
                    if msg_id == 0x631:
                        self.analyze_0x631_message(msg)
                    elif msg_id == 0x300:
                        self.analyze_radar_status(msg)
                    elif msg_id in self.critical_messages:
                        self.critical_messages[msg_id]["count"] += 1
                        self.critical_messages[msg_id]["last_seen"] = current_time

                    # Check for initialization completion
                    self.check_initialization_completion()

                    # Periodic status updates
                    if current_time - last_status_update >= 10.0:  # Every 10 seconds
                        self.print_status_update()
                        last_status_update = current_time

        except Exception as e:
            print(f"❌ Monitor error: {e}")
        finally:
            if self.bus:
                self.bus.shutdown()

        return True


def main():
    """Main function"""
    monitor = Radar631InitializationMonitor("can0")

    print("🔍 Tesla Radar 0x631 Initialization Monitor")
    print("=" * 50)
    print("🎯 Enhanced monitoring for radar initialization sequence")
    print("🔥 Specifically designed to detect 0x631 messages")
    print("⚡ Tracks power states, scan activity, and initialization phases")
    print("📡 Run this alongside tesla_complete_emulator.py")
    print()

    monitor.run()


if __name__ == "__main__":
    main()
