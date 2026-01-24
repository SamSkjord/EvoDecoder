#!/usr/bin/env python3
"""
Tesla Radar Plant Mode Checker
==============================

Simple script to check if the Tesla radar is in plant mode
and attempt to trigger VIN learning to exit plant mode.

Based on OpenPilot's patch_radar.py
"""

import can
import time
import struct
import threading
from queue import Queue, Empty
from binascii import hexlify
from enum import IntEnum

DEBUG = True


class SERVICE_TYPE(IntEnum):
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    SECURITY_ACCESS = 0x27
    READ_DATA_BY_IDENTIFIER = 0x22
    ROUTINE_CONTROL = 0x31


class SESSION_TYPE(IntEnum):
    DEFAULT = 1
    EXTENDED_DIAGNOSTIC = 3


class ACCESS_TYPE_LEVEL_1(IntEnum):
    REQUEST_SEED = 0x11
    SEND_KEY = 0x12


class ROUTINE_CONTROL_TYPE(IntEnum):
    START = 1
    STOP = 2
    REQUEST_RESULTS = 3


class TeslaRadarPlantModeCheck:
    """Tesla Radar Plant Mode Checker"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None
        self.tx_addr = 0x641
        self.rx_addr = 0x651
        self.tx_queue = Queue()
        self.rx_queue = Queue()
        self.running = False

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

    def start_isotp_thread(self):
        """Start ISOTP communication thread"""
        self.running = True
        self.isotp_thread = threading.Thread(target=self._isotp_handler)
        self.isotp_thread.daemon = True
        self.isotp_thread.start()

    def _isotp_handler(self):
        """Handle ISOTP communication"""
        while self.running:
            try:
                # Handle incoming messages
                message = self.bus.recv(timeout=0.01)
                if message and message.arbitration_id == self.rx_addr:
                    rx_data = bytearray(message.data)
                    if DEBUG:
                        print(
                            f"R: {hex(message.arbitration_id)} {hexlify(rx_data).decode()}"
                        )

                    # Extract single frame payload
                    if rx_data[0] >> 4 == 0x0:
                        frame_size = rx_data[0] & 0x0F
                        frame_data = rx_data[1 : 1 + frame_size]
                        self.rx_queue.put(frame_data)
                        if DEBUG:
                            print(f"   Payload: {hexlify(frame_data).decode()}")

                # Handle outgoing messages
                if not self.tx_queue.empty():
                    req_data = self.tx_queue.get(block=False)
                    if len(req_data) <= 7:
                        msg_data = bytes([len(req_data)]) + req_data
                        msg_data = msg_data.ljust(8, b"\x00")
                        if DEBUG:
                            print(
                                f"S: {hex(self.tx_addr)} {hexlify(msg_data).decode()}"
                            )
                        self.bus.send(
                            can.Message(arbitration_id=self.tx_addr, data=msg_data)
                        )

            except Exception as e:
                if self.running:
                    print(f"❌ ISOTP error: {e}")
                time.sleep(0.001)

    def _uds_request(self, service_type, subfunction=None, data=None):
        """Generic UDS request"""
        req = bytes([service_type])
        if subfunction is not None:
            req += bytes([subfunction])
        if data is not None:
            req += data

        self.tx_queue.put(req)

        try:
            resp = self.rx_queue.get(block=True, timeout=3)
        except Empty:
            raise Exception("Timeout waiting for UDS response")

        if len(resp) == 0:
            raise Exception("Empty UDS response")

        resp_sid = resp[0]

        # Check for negative response
        if resp_sid == 0x7F:
            service_id = resp[1] if len(resp) > 1 else -1
            error_code = resp[2] if len(resp) > 2 else -1
            raise Exception(
                f"UDS negative response: service {service_id:02X}, error {error_code:02X}"
            )

        # Check positive response
        if service_type + 0x40 != resp_sid:
            raise Exception(
                f"Invalid response service ID: expected {service_type + 0x40:02X}, got {resp_sid:02X}"
            )

        # Return data (exclude service ID and subfunction)
        return resp[(1 if subfunction is None else 2) :]

    def diagnostic_session_control(self, session_type):
        """UDS Diagnostic Session Control"""
        print(f"📋 Setting diagnostic session: {session_type}")
        self._uds_request(
            SERVICE_TYPE.DIAGNOSTIC_SESSION_CONTROL, subfunction=session_type
        )

    def security_access(self, access_type, key=None):
        """UDS Security Access"""
        if access_type % 2 != 0:  # Request seed
            print(f"🔒 Requesting security seed (level {access_type})")
            resp = self._uds_request(
                SERVICE_TYPE.SECURITY_ACCESS, subfunction=access_type
            )
            return resp
        else:  # Send key
            print(f"🔑 Sending security key (level {access_type})")
            self._uds_request(
                SERVICE_TYPE.SECURITY_ACCESS, subfunction=access_type, data=key
            )

    def read_data_by_identifier(self, data_id):
        """UDS Read Data By Identifier"""
        print(f"📖 Reading data identifier {data_id:04X}")
        data = struct.pack("!H", data_id)
        resp = self._uds_request(SERVICE_TYPE.READ_DATA_BY_IDENTIFIER, data=data)
        return resp[2:]  # Skip identifier echo

    def routine_control(self, control_type, routine_id, data=None):
        """UDS Routine Control"""
        print(f"🔄 Routine control: {control_type} on routine {routine_id}")
        req_data = struct.pack("!H", routine_id)
        if data:
            req_data += data
        return self._uds_request(
            SERVICE_TYPE.ROUTINE_CONTROL, subfunction=control_type, data=req_data
        )

    def tesla_radar_security_algorithm(self, seed):
        """Tesla radar security access algorithm"""
        seed_int = int.from_bytes(seed, byteorder="big")

        # Implementation from OpenPilot
        k4 = (
            ((seed_int >> 5) & 8)
            | ((seed_int >> 0xB) & 4)
            | ((seed_int >> 0x18) & 1)
            | ((seed_int >> 1) & 2)
        )

        if seed_int & 0x20000 == 0:
            k32 = (
                seed_int & ~(0xFF << k4 & 0xFFFFFFFF)
            ) << 0x20 - k4 & 0xFFFFFFFF | seed_int >> k4 & 0xFFFFFFFF
        else:
            k32 = (
                ~(0xFF << k4 & 0xFFFFFFFF) << 0x20 - k4 & seed_int & 0xFFFFFFFF
            ) >> 0x20 - k4 & 0xFFFFFFFF | seed_int << k4 & 0xFFFFFFFF

        k2 = seed_int >> 4 & 2 | seed_int >> 0x1F

        if k2 == 0:
            key_int = k32 | seed_int
        elif k2 == 1:
            key_int = k32 & seed_int
        elif k2 == 2:
            key_int = k32 ^ seed_int
        else:
            key_int = k32

        return struct.pack("!I", key_int)

    def check_plant_mode(self):
        """Check if radar is in plant mode"""
        print("🌱 CHECKING PLANT MODE STATUS")
        print("=" * 40)

        try:
            # Step 1: Default diagnostic session
            self.diagnostic_session_control(SESSION_TYPE.DEFAULT)
            time.sleep(0.1)

            # Step 2: Extended diagnostic session
            self.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
            time.sleep(0.1)

            # Step 3: Read plant mode status
            plant_mode_data = self.read_data_by_identifier(0xA022)
            plant_mode_str = plant_mode_data.decode("utf-8", errors="ignore")
            print(
                f"🌱 Plant mode status: '{plant_mode_str}' [{hexlify(plant_mode_data).decode()}]"
            )

            # Step 4: Read VIN
            try:
                vin_data = self.read_data_by_identifier(0xF190)
                vin_str = vin_data.decode("utf-8", errors="ignore")
                print(f"🆔 VIN: '{vin_str}' [{hexlify(vin_data).decode()}]")
            except Exception as e:
                print(f"⚠️  Could not read VIN: {e}")

            # Step 5: Check if plant mode indicates we need to exit
            if "plant" in plant_mode_str.lower() or plant_mode_str == "1":
                print("❌ RADAR IS IN PLANT MODE - Need to exit!")
                return True
            else:
                print("✅ RADAR NOT IN PLANT MODE")
                return False

        except Exception as e:
            print(f"❌ Plant mode check failed: {e}")
            return None

    def attempt_plant_mode_exit(self):
        """Attempt to exit plant mode via VIN learning"""
        print("\n🚀 ATTEMPTING PLANT MODE EXIT VIA VIN LEARNING")
        print("=" * 50)

        try:
            # Step 1: Security access
            seed = self.security_access(ACCESS_TYPE_LEVEL_1.REQUEST_SEED)
            print(f"🌱 Security seed: {hexlify(seed).decode()}")

            key = self.tesla_radar_security_algorithm(seed)
            print(f"🔑 Security key: {hexlify(key).decode()}")

            self.security_access(ACCESS_TYPE_LEVEL_1.SEND_KEY, key)
            print("✅ Security access successful!")

            # Step 2: Start VIN learning routine (ID 2563)
            print("🔄 Starting VIN learning routine...")
            self.routine_control(ROUTINE_CONTROL_TYPE.START, 2563)

            # Step 3: Wait a bit then stop
            time.sleep(4)

            print("⏹️  Stopping VIN learning routine...")
            self.routine_control(ROUTINE_CONTROL_TYPE.STOP, 2563)

            # Step 4: Get results
            print("📋 Getting VIN learning results...")
            results = self.routine_control(ROUTINE_CONTROL_TYPE.REQUEST_RESULTS, 2563)
            print(f"✅ VIN learning results: {hexlify(results).decode()}")

            return True

        except Exception as e:
            print(f"❌ Plant mode exit failed: {e}")
            return False

    def run_check(self):
        """Run the complete plant mode check"""
        print("🔧 Tesla Radar Plant Mode Checker")
        print("=" * 40)

        if not self.setup_can():
            return False

        self.start_isotp_thread()
        time.sleep(0.5)

        # Check current plant mode status
        is_plant_mode = self.check_plant_mode()

        if is_plant_mode is True:
            print("\n🎯 RADAR IS IN PLANT MODE - ATTEMPTING EXIT...")
            success = self.attempt_plant_mode_exit()

            if success:
                print("\n🔍 Re-checking plant mode status...")
                time.sleep(1)
                is_plant_mode = self.check_plant_mode()

                if is_plant_mode is False:
                    print("\n🎉 SUCCESS! Plant mode exit confirmed!")
                    print("   Now run radar_troubleshoot.py to check for 0x631")
                else:
                    print(
                        "\n⚠️  Plant mode exit attempted but radar still in plant mode"
                    )
            else:
                print("\n❌ Plant mode exit failed")

        elif is_plant_mode is False:
            print("\n✅ RADAR IS NOT IN PLANT MODE")
            print("   Radar should be ready for normal operation")

        else:
            print("\n❌ Could not determine plant mode status")

        self.running = False
        return True


def main():
    """Main function"""
    checker = TeslaRadarPlantModeCheck("can1")

    try:
        checker.run_check()
    except KeyboardInterrupt:
        print("\n⚠️ Check interrupted by user")
    except Exception as e:
        print(f"\n❌ Check failed: {e}")
    finally:
        if checker.bus:
            checker.bus.shutdown()


if __name__ == "__main__":
    main()
