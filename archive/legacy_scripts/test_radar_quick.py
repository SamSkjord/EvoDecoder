#!/usr/bin/env python3
"""
Quick Tesla Radar Test
Simple test to verify the complete implementation works
"""

import os
import can
import time
import sys
from tesla_radar_protocol import TeslaRadarProtocol, setup_can


def quick_test():
    """Quick test of the Tesla radar implementation"""
    print("🧪 QUICK TESLA RADAR TEST")
    print("=" * 50)

    # Setup CAN
    try:
        can_bus = setup_can(interface="can1")
        print("✅ CAN interface setup successful")
    except Exception as e:
        print(f"❌ CAN setup failed: {e}")
        return False

    try:
        # Create protocol
        protocol = TeslaRadarProtocol(can_bus, debug=True)
        print("✅ Tesla protocol created")

        # Test configuration for 2016 Model S
        protocol.radarPosition = 0
        protocol.radarEpasType = 0
        protocol.actual_speed_kph = 30

        print(f"📡 Configuration:")
        print(f"   VIN: {protocol.radar_VIN}")
        print(f"   Position: {protocol.radarPosition}")
        print(f"   EPAS: {protocol.radarEpasType}")
        print(f"   Speed: {protocol.actual_speed_kph} km/h")
        print()

        print("🚀 Starting Tesla protocol (30 seconds)...")
        print("Looking for 0x631 initialization and 0x300 status messages...")
        print()

        # Start protocol in background
        import threading

        protocol_thread = threading.Thread(target=protocol.start)
        protocol_thread.daemon = True
        protocol_thread.start()

        # Monitor for key messages
        start_time = time.time()
        init_count = 0
        status_count = 0
        vin_complete = 0

        while time.time() - start_time < 30:
            time.sleep(0.1)

            if protocol.init_message_count != init_count:
                init_count = protocol.init_message_count
                data = (
                    protocol.last_init_data.hex()
                    if protocol.last_init_data is not None
                    else "<no data>"
                )
                print(f"🔄 INIT MESSAGE #{init_count}: 0x631 = {data}")

            if protocol.status_message_count != status_count:
                status_count = protocol.status_message_count
                if status_count % 10 == 0 and protocol.last_status_data is not None:
                    scan_index = protocol.last_status_data[1]
                    power = protocol.last_status_data[2]
                    print(
                        f"📊 STATUS #{status_count}: Scan={scan_index}, Power={power}"
                    )

            if protocol.tesla_radar_vin_complete != vin_complete:
                vin_complete = protocol.tesla_radar_vin_complete
                print(f"📡 VIN transmission: {vin_complete}/7 cycles")

        # Stop protocol
        protocol.stop()

        # Results
        print(f"\n📊 TEST RESULTS:")
        print(f"   Init messages (0x631): {init_count}")
        print(f"   Status messages (0x300): {status_count}")
        print(f"   VIN completion: {vin_complete}/7")
        print(f"   Final radar status: {protocol.tesla_radar_status}")

        if init_count > 0:
            print("✅ Radar initialization detected!")
        else:
            print("❌ No radar initialization - check connections")

        if status_count > 0:
            print("✅ Radar status messages received!")
        else:
            print("❌ No status messages - radar may not be responding")

        if vin_complete >= 7:
            print("✅ VIN transmission complete!")
        else:
            print("⚠️  VIN transmission incomplete")

        return init_count > 0 and status_count > 0

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False
    finally:
        can_bus.shutdown()
        print("\n🔌 CAN interface closed")


if __name__ == "__main__":
    print("Tesla Radar Quick Test")
    print("Make sure your Pi is connected to the radar and CAN interfaces are up")
    print()

    if sys.stdin.isatty():
        input("Press Enter to start test...")
    else:
        print("Non-interactive environment detected, starting test automatically...")

    success = quick_test()

    if success:
        print("\n🎉 QUICK TEST PASSED!")
        print("Ready to run full activation test:")
        print("python3 tesla_radar_activator.py --debug")
    else:
        print("\n❌ QUICK TEST FAILED!")
        print("Check connections and try again")
