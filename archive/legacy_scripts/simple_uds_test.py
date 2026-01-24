#!/usr/bin/env python3
"""
Simple UDS Test
===============

Send the exact same UDS message that worked in the scanner
"""

import can
import time
from binascii import hexlify


def simple_uds_test():
    """Simple UDS test - send extended diagnostic session"""

    # Setup CAN
    bus = can.interface.Bus(channel="can1", bustype="socketcan")

    # The exact message that worked in the scanner
    uds_msg = b"\x02\x10\x03\x00\x00\x00\x00\x00"  # Extended diagnostic session

    print("📡 Sending UDS message...")
    print(f"   TX: 0x641 -> {hexlify(uds_msg).decode()}")

    # Send message
    msg = can.Message(arbitration_id=0x641, data=uds_msg, is_extended_id=False)
    bus.send(msg)

    # Wait for response
    print("👂 Waiting for response...")
    start_time = time.time()

    while (time.time() - start_time) < 2:
        message = bus.recv(timeout=0.1)
        if message:
            print(
                f"   RX: {message.arbitration_id:03X} -> {hexlify(message.data).decode()}"
            )

            # Check if it's our expected response
            if message.arbitration_id == 0x651:
                print("✅ Got response from radar!")

                # Parse the response
                data = message.data
                if len(data) > 0:
                    frame_type = data[0] >> 4
                    if frame_type == 0:  # Single frame
                        frame_size = data[0] & 0x0F
                        payload = data[1 : 1 + frame_size]
                        print(f"   Frame type: Single frame")
                        print(f"   Frame size: {frame_size} bytes")
                        print(f"   Payload: {hexlify(payload).decode()}")

                        if len(payload) > 0:
                            service_id = payload[0]
                            if service_id == 0x50:  # 0x10 + 0x40
                                print(
                                    "✅ Positive response to diagnostic session control!"
                                )
                                print(
                                    f"   Session type: {payload[1] if len(payload) > 1 else 'unknown'}"
                                )
                                print(
                                    f"   Session data: {hexlify(payload[2:]).decode()}"
                                )
                                return True
                            elif service_id == 0x7F:
                                print("❌ Negative response")
                                if len(payload) >= 3:
                                    print(f"   Service: {payload[1]:02X}")
                                    print(f"   Error: {payload[2]:02X}")
                                return False

                return True

    print("❌ No response received")
    bus.shutdown()
    return False


if __name__ == "__main__":
    print("🔧 Simple UDS Test")
    print("=" * 30)

    success = simple_uds_test()

    if success:
        print("\n✅ UDS communication working!")
        print("   Now we can implement proper plant mode exit")
    else:
        print("\n❌ UDS communication failed")
