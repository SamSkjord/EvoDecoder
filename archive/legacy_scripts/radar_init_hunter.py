#!/usr/bin/env python3
"""
Tesla Radar Initialization Hunter
=================================

This script tries to find what triggers the radar to send 0x631 initialization message.
We'll try different approaches to wake up the radar properly.
"""

import can
import time
import struct
import threading
from collections import defaultdict, deque


class RadarInitHunter:
    """Hunt for the proper radar initialization sequence"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None
        self.running = False
        self.received_messages = defaultdict(list)
        self.init_attempts = []

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

    def monitor_all_messages(self):
        """Monitor all CAN messages looking for 0x631"""
        print("👂 Monitoring ALL CAN messages...")

        while self.running:
            try:
                message = self.bus.recv(timeout=0.1)
                if message:
                    self.received_messages[message.arbitration_id].append(
                        {"timestamp": time.time(), "data": message.data.hex()}
                    )

                    # Look for the holy grail - 0x631 initialization
                    if message.arbitration_id == 0x631:
                        print(f"🎯 FOUND 0x631 INITIALIZATION: {message.data.hex()}")

                    # Also log any new message IDs we haven't seen
                    if len(self.received_messages[message.arbitration_id]) == 1:
                        print(
                            f"📡 New message ID: {message.arbitration_id:03X} = {message.data.hex()}"
                        )

            except Exception as e:
                if self.running:
                    print(f"❌ Receive error: {e}")
                break

    def try_power_cycle_sequence(self):
        """Try different power cycle sequences"""
        print("🔄 Trying power cycle sequences...")

        # Method 1: Send silence (no messages) for a period
        print("   Method 1: Radio silence for 10 seconds...")
        time.sleep(10)

        # Method 2: Send a wake-up message
        print("   Method 2: Sending potential wake-up messages...")
        wake_up_messages = [
            (
                0x17C,
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
            ),  # trigger_message_id from safety
            (
                0x560,
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
            ),  # config_message_id from safety
            (0x631, b"\x00\x00\x00\x00\x00\x00\x00\x00"),  # try sending 0x631 ourselves
        ]

        for msg_id, data in wake_up_messages:
            try:
                msg = can.Message(
                    arbitration_id=msg_id, data=data, is_extended_id=False
                )
                self.bus.send(msg)
                print(f"   Sent wake-up: {msg_id:03X} = {data.hex()}")
                time.sleep(1)
            except Exception as e:
                print(f"   Failed to send {msg_id:03X}: {e}")

    def try_minimal_tesla_protocol(self):
        """Try minimal Tesla protocol to see if it triggers initialization"""
        print("🚗 Trying minimal Tesla protocol...")

        # Send just the most critical messages
        essential_messages = [
            (0x199, b"\x06\x00\x00\x00\x00\x00\x00\x00"),  # DI_state
            (0x2A9, b"\x00\x00\x00\x00\x00\x00\x00\x00"),  # radarState
            (0x2D9, b"\x01\x00\x00\x00\x00\x00\x00\x00"),  # DI_radarConfig
        ]

        for _ in range(50):  # Send for 5 seconds
            for msg_id, data in essential_messages:
                try:
                    msg = can.Message(
                        arbitration_id=msg_id, data=data, is_extended_id=False
                    )
                    self.bus.send(msg)
                except Exception as e:
                    print(f"Failed to send {msg_id:03X}: {e}")
            time.sleep(0.1)

    def try_vin_learning_sequence(self):
        """Try VIN learning sequence"""
        print("🆔 Trying VIN learning sequence...")

        vin = "5YJSB7E43GF113105"

        # Send VIN in 3 parts as per Tesla protocol
        for cycle in range(10):  # Send multiple cycles
            # Part 1: chars 0-2
            data = [0x10] + [ord(c) for c in vin[0:3]] + [0x00] * 4
            msg = can.Message(
                arbitration_id=0x2B9, data=bytes(data[:8]), is_extended_id=False
            )
            self.bus.send(msg)
            time.sleep(0.25)

            # Part 2: chars 3-9
            data = [0x11] + [ord(c) for c in vin[3:10]] + [0x00] * 0
            msg = can.Message(
                arbitration_id=0x2B9, data=bytes(data[:8]), is_extended_id=False
            )
            self.bus.send(msg)
            time.sleep(0.25)

            # Part 3: chars 10-16
            data = [0x12] + [ord(c) for c in vin[10:17]] + [0x00] * 0
            msg = can.Message(
                arbitration_id=0x2B9, data=bytes(data[:8]), is_extended_id=False
            )
            self.bus.send(msg)
            time.sleep(0.25)

            print(f"   VIN learning cycle {cycle + 1}/10 complete")

    def analyze_results(self):
        """Analyze what we found"""
        print("\n📊 ANALYSIS RESULTS:")
        print("=" * 50)

        # Check if we found 0x631
        if 0x631 in self.received_messages:
            print("🎯 SUCCESS: Found 0x631 initialization messages!")
            for msg in self.received_messages[0x631]:
                print(f"   {msg['timestamp']}: {msg['data']}")
        else:
            print("❌ FAILED: No 0x631 initialization message detected")

        # Show all unique message IDs we saw
        print(f"\n📡 Total unique message IDs seen: {len(self.received_messages)}")
        for msg_id in sorted(self.received_messages.keys()):
            count = len(self.received_messages[msg_id])
            last_data = self.received_messages[msg_id][-1]["data"]
            print(f"   {msg_id:03X}: {count} messages, last: {last_data}")

        # Check for any patterns
        print("\n🔍 Pattern Analysis:")
        for msg_id, messages in self.received_messages.items():
            if len(messages) > 1:
                unique_data = set(msg["data"] for msg in messages)
                if len(unique_data) == 1:
                    print(f"   {msg_id:03X}: STATIC data - {list(unique_data)[0]}")
                else:
                    print(
                        f"   {msg_id:03X}: DYNAMIC data - {len(unique_data)} unique values"
                    )

    def run_hunt(self):
        """Run the initialization hunt"""
        print("🔍 TESLA RADAR INITIALIZATION HUNT")
        print("=" * 50)

        if not self.setup_can():
            return

        # Start monitoring
        self.running = True
        monitor_thread = threading.Thread(target=self.monitor_all_messages)
        monitor_thread.daemon = True
        monitor_thread.start()

        # Try different initialization methods
        print("\n🎯 Phase 1: Power cycle sequences")
        self.try_power_cycle_sequence()

        print("\n🎯 Phase 2: VIN learning sequence")
        self.try_vin_learning_sequence()

        print("\n🎯 Phase 3: Minimal Tesla protocol")
        self.try_minimal_tesla_protocol()

        print("\n🎯 Phase 4: Final observation period")
        time.sleep(10)

        # Stop monitoring
        self.running = False

        # Analyze results
        self.analyze_results()

        return self.received_messages


def main():
    """Main function"""
    print("🔧 Tesla Radar Initialization Hunter")
    print("Looking for the missing 0x631 initialization message...")
    print()

    hunter = RadarInitHunter("can1")
    results = hunter.run_hunt()

    print("\n🎯 CONCLUSION:")
    if 0x631 in results:
        print("✅ Found initialization sequence! Ready to implement proper activation.")
    else:
        print(
            "❌ Initialization sequence not found. Radar may need hardware reset or different approach."
        )


if __name__ == "__main__":
    main()
