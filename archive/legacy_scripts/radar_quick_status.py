#!/usr/bin/env python3
"""
Tesla Radar Quick Status Check
=============================

Quick diagnostic tool to check current radar status and activity.
Provides immediate feedback on:
- CAN bus activity
- Tesla protocol messages
- 0x631 initialization status
- Current radar state

Use this for quick status checks without long monitoring sessions.
"""

import can
import time
import sys
from collections import defaultdict


class RadarQuickStatus:
    """Quick radar status checker"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None

    def setup_can(self) -> bool:
        """Setup CAN interface"""
        try:
            self.bus = can.interface.Bus(
                channel=self.can_interface, interface="socketcan"
            )
            return True
        except Exception as e:
            print(f"❌ CAN setup failed: {e}")
            return False

    def quick_scan(self, duration: int = 10):
        """Perform quick scan of CAN activity"""
        print(f"🔍 Quick Radar Status Check ({duration}s)")
        print("=" * 50)
        print(f"Interface: {self.can_interface}")
        print("Scanning for radar activity...")
        print()

        message_counts = defaultdict(int)
        tesla_messages = {
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
        x631_count = 0
        x631_patterns = set()
        scan_indices = set()

        start_time = time.time()
        end_time = start_time + duration

        try:
            while time.time() < end_time:
                msg = self.bus.recv(timeout=1.0)

                if msg:
                    msg_id = msg.arbitration_id
                    message_counts[msg_id] += 1

                    # Track specific messages
                    if msg_id == 0x631:
                        x631_count += 1
                        x631_patterns.add(msg.data.hex().upper())
                        if x631_count <= 3:  # Show first few
                            print(f"🔥 0x631 #{x631_count}: {msg.data.hex().upper()}")

                    elif msg_id == 0x300:
                        if len(msg.data) >= 1:
                            scan_indices.add(msg.data[0])

                # Progress indicator
                elapsed = time.time() - start_time
                if int(elapsed) % 2 == 0 and elapsed > 0:
                    remaining = duration - elapsed
                    print(f"⏳ Scanning... {remaining:.0f}s remaining")

        except KeyboardInterrupt:
            print("\n⚠️  Scan interrupted")
        except Exception as e:
            print(f"❌ Scan error: {e}")

        # Analysis
        print(f"\n📊 QUICK STATUS RESULTS")
        print("=" * 50)

        # Overall activity
        total_messages = sum(message_counts.values())
        active_ids = len(message_counts)
        print(f"📨 Total activity: {total_messages} messages, {active_ids} unique IDs")

        # Tesla protocol check
        tesla_active = sum(1 for tid in tesla_messages if message_counts[tid] > 0)
        print(f"🚗 Tesla protocol: {tesla_active}/{len(tesla_messages)} message types")
        if tesla_active > 0:
            active_tesla = [
                f"0x{tid:03X}" for tid in tesla_messages if message_counts[tid] > 0
            ]
            print(f"   Active: {', '.join(active_tesla)}")

        # 0x631 status
        print(f"🔥 0x631 initialization: {x631_count} messages")
        if x631_count > 0:
            print(f"   Patterns: {len(x631_patterns)} unique")
            print("   Status: ✅ INITIALIZATION ACTIVE")
        else:
            print("   Status: ❌ NOT DETECTED")

        # Scan status
        print(f"📡 Scan indices: {len(scan_indices)} unique values")
        if len(scan_indices) > 1:
            print("   Status: ✅ DYNAMIC SCANNING")
        elif len(scan_indices) == 1:
            print("   Status: ⚠️  STATIC SCANNING")
        else:
            print("   Status: ❌ NO SCAN DATA")

        # Top active messages
        if message_counts:
            print(f"\n📈 TOP ACTIVE MESSAGES:")
            sorted_msgs = sorted(
                message_counts.items(), key=lambda x: x[1], reverse=True
            )[:8]
            for msg_id, count in sorted_msgs:
                rate = count / duration
                print(f"   0x{msg_id:03X}: {count:4d} messages ({rate:.1f}Hz)")

        # Assessment
        print(f"\n🎯 QUICK ASSESSMENT:")
        if x631_count > 0 and len(scan_indices) > 3:
            print("   ✅ RADAR APPEARS FULLY ACTIVE!")
            print("   🎉 Initialization and scanning detected")
        elif x631_count > 0:
            print("   🔥 RADAR INITIALIZING!")
            print("   ⏳ Waiting for dynamic scanning")
        elif tesla_active >= 4:
            print("   ⚡ TESLA PROTOCOL ACTIVE!")
            print("   ⏳ Waiting for radar initialization")
        elif total_messages > 0:
            print("   📡 CAN ACTIVITY DETECTED")
            print("   ⏳ Waiting for Tesla protocol")
        else:
            print("   ❌ NO SIGNIFICANT ACTIVITY")
            print("   🔧 Check Tesla protocol emulator")

    def run(self):
        """Run quick status check"""
        if not self.setup_can():
            return False

        try:
            self.quick_scan(10)  # 10 second scan
        finally:
            if self.bus:
                self.bus.shutdown()

        return True


def main():
    """Main function"""
    print("🔧 Tesla Radar Quick Status Check")
    print("=" * 50)
    print("⚡ Fast diagnostic for current radar state")
    print("🎯 10-second scan for immediate status")
    print()

    checker = RadarQuickStatus("can1")
    checker.run()


if __name__ == "__main__":
    main()
