#!/usr/bin/env python3
"""
Tesla Radar 0x631 Monitor
========================

Monitors CAN bus for the critical 0x631 initialization message
that indicates the radar is fully activated and ready to transmit.
"""

import can
import time
from binascii import hexlify
import signal
import sys


class Radar631Monitor:
    """Monitor for Tesla radar 0x631 initialization message"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None
        self.running = False
        self.found_631 = False
        self.scan_index_counts = {}
        self.message_counts = {}

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

    def monitor_loop(self):
        """Main monitoring loop"""
        print("🔍 Tesla Radar 0x631 Monitor")
        print("=" * 50)
        print("🎯 Watching for 0x631 initialization message...")
        print("📊 Also monitoring scan index changes and message patterns")
        print()

        last_status_time = time.time()
        start_time = time.time()

        while self.running:
            try:
                message = self.bus.recv(timeout=0.1)

                if message:
                    msg_id = message.arbitration_id

                    # Count all messages
                    self.message_counts[msg_id] = self.message_counts.get(msg_id, 0) + 1

                    # Check for 0x631 initialization
                    if msg_id == 0x631:
                        if not self.found_631:
                            print(f"🎉 FOUND 0x631 INITIALIZATION MESSAGE!")
                            print(
                                f"   Time: {time.time() - start_time:.1f}s since start"
                            )
                            print(f"   Data: {hexlify(message.data).decode()}")
                            self.found_631 = True
                        else:
                            print(f"🔄 0x631: {hexlify(message.data).decode()}")

                    # Monitor scan index changes (0x300)
                    elif msg_id == 0x300:
                        if len(message.data) >= 1:
                            scan_index = message.data[0]
                            self.scan_index_counts[scan_index] = (
                                self.scan_index_counts.get(scan_index, 0) + 1
                            )

                    # Monitor other important radar messages
                    elif msg_id in [0x651, 0x17C, 0x169, 0x199, 0x119, 0x109]:
                        # These are important - log occasionally
                        if (
                            self.message_counts[msg_id] % 100 == 1
                        ):  # Every 100th message
                            print(f"📡 {msg_id:03X}: {hexlify(message.data).decode()}")

                # Status update every 10 seconds
                if time.time() - last_status_time >= 10:
                    self.print_status(time.time() - start_time)
                    last_status_time = time.time()

            except Exception as e:
                if "timed out" not in str(e).lower():
                    print(f"⚠️  Monitor error: {e}")
                continue

    def print_status(self, elapsed_time: float):
        """Print current status"""
        print(f"\n📊 STATUS UPDATE - {elapsed_time:.1f}s elapsed")
        print("=" * 40)

        # 0x631 status
        if self.found_631:
            print("✅ 0x631 INITIALIZATION: DETECTED!")
        else:
            print("❌ 0x631 INITIALIZATION: NOT DETECTED")

        # Scan index analysis
        if self.scan_index_counts:
            unique_scan_indices = len(self.scan_index_counts)
            most_common_scan = max(self.scan_index_counts.items(), key=lambda x: x[1])

            print(f"📡 Scan indices: {unique_scan_indices} unique values")
            print(
                f"   Most common: 0x{most_common_scan[0]:02X} ({most_common_scan[1]} times)"
            )

            if unique_scan_indices > 1:
                print("   ✅ Scan index CHANGING (radar scanning)")
            else:
                print("   ❌ Scan index STATIC (plant mode?)")

        # Message activity
        active_messages = len(self.message_counts)
        print(f"📨 Active CAN IDs: {active_messages}")

        # Top 5 most active messages
        if self.message_counts:
            top_messages = sorted(
                self.message_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]
            print("   Top active messages:")
            for msg_id, count in top_messages:
                print(f"     0x{msg_id:03X}: {count} messages")

        print()

    def run(self):
        """Start monitoring"""
        if not self.setup_can():
            return False

        self.running = True

        def signal_handler(sig, frame):
            print("\n🛑 Stopping 0x631 Monitor...")
            self.running = False

            # Final summary
            print("\n📋 FINAL SUMMARY:")
            print("=" * 30)
            if self.found_631:
                print("🎉 SUCCESS: 0x631 initialization detected!")
                print("   Radar should be fully activated!")
            else:
                print("❌ 0x631 initialization NOT detected")
                print("   Radar not fully activated")

            if self.scan_index_counts:
                print(
                    f"📡 Scan index values seen: {list(self.scan_index_counts.keys())}"
                )
                if len(self.scan_index_counts) > 1:
                    print("   ✅ Dynamic scanning detected")
                else:
                    print("   ❌ Static scanning only")

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
    monitor = Radar631Monitor("can1")

    print("🔧 Tesla Radar 0x631 Monitor")
    print("=" * 50)
    print("🎯 This monitor watches for the critical 0x631 message")
    print("   that indicates full radar activation")
    print("⚠️  Keep the vehicle emulator running in another terminal!")
    print()

    monitor.run()


if __name__ == "__main__":
    main()
