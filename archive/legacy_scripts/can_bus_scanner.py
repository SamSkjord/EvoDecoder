#!/usr/bin/env python3
"""
CAN Bus Scanner
===============

Scans both CAN buses to find active addresses and see where the radar is responding.
"""

import can
import time
import threading
from collections import defaultdict, deque


class CANBusScanner:
    """Scan CAN buses to find active addresses"""

    def __init__(self):
        self.can0_bus = None
        self.can1_bus = None
        self.running = False
        self.can0_messages = defaultdict(list)
        self.can1_messages = defaultdict(list)

    def setup_can_buses(self):
        """Setup both CAN interfaces"""
        try:
            self.can0_bus = can.interface.Bus(channel="can0", bustype="socketcan")
            print("✅ CAN0 interface setup successful")
        except Exception as e:
            print(f"❌ CAN0 interface setup failed: {e}")

        try:
            self.can1_bus = can.interface.Bus(channel="can1", bustype="socketcan")
            print("✅ CAN1 interface setup successful")
        except Exception as e:
            print(f"❌ CAN1 interface setup failed: {e}")

    def monitor_can0(self):
        """Monitor CAN0 bus"""
        if not self.can0_bus:
            return

        print("👂 Monitoring CAN0...")
        while self.running:
            try:
                message = self.can0_bus.recv(timeout=0.1)
                if message:
                    self.can0_messages[message.arbitration_id].append(
                        {"timestamp": time.time(), "data": message.data.hex()}
                    )
            except Exception as e:
                if self.running:
                    print(f"❌ CAN0 error: {e}")
                break

    def monitor_can1(self):
        """Monitor CAN1 bus"""
        if not self.can1_bus:
            return

        print("👂 Monitoring CAN1...")
        while self.running:
            try:
                message = self.can1_bus.recv(timeout=0.1)
                if message:
                    self.can1_messages[message.arbitration_id].append(
                        {"timestamp": time.time(), "data": message.data.hex()}
                    )
            except Exception as e:
                if self.running:
                    print(f"❌ CAN1 error: {e}")
                break

    def try_uds_on_addresses(self, bus, bus_name, test_addresses):
        """Try UDS diagnostic session on various addresses"""
        print(f"\n🔍 Testing UDS addresses on {bus_name}:")

        if not bus:
            print(f"   {bus_name} not available")
            return

        # UDS diagnostic session control message
        uds_msg = b"\x02\x10\x03\x00\x00\x00\x00\x00"  # Extended diagnostic session

        for addr in test_addresses:
            try:
                print(f"   Testing UDS on {addr:03X}...")
                msg = can.Message(
                    arbitration_id=addr, data=uds_msg, is_extended_id=False
                )
                bus.send(msg)
                time.sleep(0.1)

                # Check for response on addr + 0x10
                response_addr = addr + 0x10
                found_response = False

                # Check recent messages for response
                if bus_name == "CAN0":
                    messages = self.can0_messages
                else:
                    messages = self.can1_messages

                if response_addr in messages:
                    recent_messages = [
                        m
                        for m in messages[response_addr]
                        if time.time() - m["timestamp"] < 1.0
                    ]
                    if recent_messages:
                        print(
                            f"   ✅ Response found on {response_addr:03X}: {recent_messages[-1]['data']}"
                        )
                        found_response = True

                if not found_response:
                    print(f"   ❌ No response on {response_addr:03X}")

            except Exception as e:
                print(f"   ❌ Error testing {addr:03X}: {e}")

    def analyze_results(self):
        """Analyze scan results"""
        print("\n📊 CAN BUS SCAN RESULTS:")
        print("=" * 50)

        print(f"\n🔍 CAN0 Active Addresses: {len(self.can0_messages)}")
        for addr in sorted(self.can0_messages.keys()):
            count = len(self.can0_messages[addr])
            last_data = self.can0_messages[addr][-1]["data"]
            print(f"   {addr:03X}: {count} messages, last: {last_data}")

        print(f"\n🔍 CAN1 Active Addresses: {len(self.can1_messages)}")
        for addr in sorted(self.can1_messages.keys()):
            count = len(self.can1_messages[addr])
            last_data = self.can1_messages[addr][-1]["data"]
            print(f"   {addr:03X}: {count} messages, last: {last_data}")

        # Look for potential UDS addresses
        print("\n🎯 POTENTIAL UDS ADDRESSES:")

        # Common Tesla radar UDS addresses
        potential_uds = [0x641, 0x651, 0x7C0, 0x7C8, 0x7DF, 0x7E0, 0x7E8]

        for addr in potential_uds:
            found_on = []
            if addr in self.can0_messages:
                found_on.append("CAN0")
            if addr in self.can1_messages:
                found_on.append("CAN1")

            if found_on:
                print(f"   {addr:03X}: Found on {', '.join(found_on)}")
            else:
                print(f"   {addr:03X}: Not found")

    def run_scan(self, duration=30):
        """Run the complete scan"""
        print("🔍 CAN BUS SCANNER")
        print("=" * 30)

        self.setup_can_buses()

        if not self.can0_bus and not self.can1_bus:
            print("❌ No CAN buses available")
            return

        # Start monitoring threads
        self.running = True

        threads = []
        if self.can0_bus:
            can0_thread = threading.Thread(target=self.monitor_can0)
            can0_thread.daemon = True
            can0_thread.start()
            threads.append(can0_thread)

        if self.can1_bus:
            can1_thread = threading.Thread(target=self.monitor_can1)
            can1_thread.daemon = True
            can1_thread.start()
            threads.append(can1_thread)

        # Monitor for specified duration
        print(f"📡 Monitoring for {duration} seconds...")
        time.sleep(duration)

        # Try UDS on common addresses
        test_addresses = [0x641, 0x7C0, 0x7C8, 0x7DF, 0x7E0, 0x7E8]

        if self.can0_bus:
            self.try_uds_on_addresses(self.can0_bus, "CAN0", test_addresses)

        if self.can1_bus:
            self.try_uds_on_addresses(self.can1_bus, "CAN1", test_addresses)

        # Stop monitoring
        self.running = False

        # Analyze results
        self.analyze_results()

        # Cleanup
        if self.can0_bus:
            self.can0_bus.shutdown()
        if self.can1_bus:
            self.can1_bus.shutdown()


def main():
    """Main function"""
    scanner = CANBusScanner()

    try:
        scanner.run_scan(duration=20)

        print("\n🎯 CONCLUSION:")
        print("Look for addresses that responded to UDS requests")
        print("These are potential candidates for radar communication")

    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")


if __name__ == "__main__":
    main()
