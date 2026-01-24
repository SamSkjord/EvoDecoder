#!/usr/bin/env python3
"""
Tesla Radar UDS Reset Script
============================

This script implements the UDS (Unified Diagnostic Services) sequence
to perform an ECU reset on the Tesla radar, which should trigger
plant mode exit and proper initialization.

Based on OpenPilot's programRadarVin.py
"""

import can
import time
import struct
import threading
from enum import IntEnum
from queue import Queue, Empty
from binascii import hexlify

DEBUG = True


class SERVICE_TYPE(IntEnum):
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    SECURITY_ACCESS = 0x27
    READ_DATA_BY_IDENTIFIER = 0x22
    WRITE_DATA_BY_IDENTIFIER = 0x2E


class SESSION_TYPE(IntEnum):
    DEFAULT = 1
    PROGRAMMING = 2
    EXTENDED_DIAGNOSTIC = 3


class RESET_TYPE(IntEnum):
    HARD = 1
    KEY_OFF_ON = 2
    SOFT = 3


class ACCESS_TYPE(IntEnum):
    REQUEST_SEED = 1
    SEND_KEY = 2


class DATA_IDENTIFIER_TYPE(IntEnum):
    VIN = 0xF190


class MessageTimeoutError(Exception):
    pass


class NegativeResponseError(Exception):
    def __init__(self, message, service_id, error_code):
        super(Exception, self).__init__(message)
        self.service_id = service_id
        self.error_code = error_code


class TeslaRadarUDSReset:
    """Tesla Radar UDS Reset Implementation"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None
        self.tx_addr = 0x641  # Tesla Bosch radar RCM addr
        self.rx_addr = 0x651  # Response address (tx_addr + 0x10)
        self.tx_queue = Queue()
        self.rx_queue = Queue()
        self.isotp_thread = None
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
        print("📡 ISOTP communication thread started")

    def _isotp_handler(self):
        """Handle ISOTP (ISO-TP) communication - Simplified for Tesla radar"""
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

                    # Tesla radar uses single frame responses, extract payload
                    if rx_data[0] >> 4 == 0x0:
                        # Single frame - most common for Tesla radar
                        frame_size = rx_data[0] & 0x0F
                        frame_data = rx_data[1 : 1 + frame_size]
                        self.rx_queue.put(frame_data)
                        if DEBUG:
                            print(
                                f"   Extracted payload: {hexlify(frame_data).decode()}"
                            )

                # Handle outgoing messages
                if not self.tx_queue.empty():
                    req_data = self.tx_queue.get(block=False)

                    # Tesla radar uses single frame requests
                    if len(req_data) <= 7:
                        # Single frame
                        msg_data = bytes([len(req_data)]) + req_data
                        msg_data = msg_data.ljust(8, b"\x00")
                        if DEBUG:
                            print(
                                f"S: {hex(self.tx_addr)} {hexlify(msg_data).decode()}"
                            )
                        self.bus.send(
                            can.Message(arbitration_id=self.tx_addr, data=msg_data)
                        )
                    else:
                        print(
                            f"❌ Message too long for single frame: {len(req_data)} bytes"
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

        # Wait for response
        try:
            resp = self.rx_queue.get(block=True, timeout=10)
        except Empty:
            raise MessageTimeoutError("Timeout waiting for UDS response")

        resp_sid = resp[0] if len(resp) > 0 else None

        # Check for negative response
        if resp_sid == 0x7F:
            service_id = resp[1] if len(resp) > 1 else -1
            error_code = resp[2] if len(resp) > 2 else -1

            # Response pending - wait longer
            if error_code == 0x78:
                time.sleep(0.1)
                return self._uds_request(service_type, subfunction, data)

            raise NegativeResponseError(
                f"UDS error: service {service_id:02X}, error {error_code:02X}",
                service_id,
                error_code,
            )

        # Check positive response
        if service_type + 0x40 != resp_sid:
            raise ValueError(f"Invalid response service ID: {resp_sid:02X}")

        if subfunction is not None:
            resp_sfn = resp[1] if len(resp) > 1 else None
            if subfunction != resp_sfn:
                raise ValueError(f"Invalid response subfunction: {resp_sfn:02X}")

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

    def ecu_reset(self, reset_type):
        """UDS ECU Reset"""
        print(f"🔄 Performing ECU reset: {reset_type}")
        self._uds_request(SERVICE_TYPE.ECU_RESET, subfunction=reset_type)

    def tesla_radar_security_algorithm(self, seed):
        """Tesla radar security access algorithm"""
        seed_int = struct.unpack(">L", seed)[0]

        # Implementation from OpenPilot
        k4 = (
            seed_int >> 5 & 8
            | seed_int >> 0xB & 4
            | seed_int >> 0x18 & 1
            | seed_int >> 1 & 2
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

        return struct.pack("!L", key_int)

    def perform_uds_reset_sequence(self):
        """Perform the complete UDS reset sequence"""
        print("🚀 STARTING TESLA RADAR UDS RESET SEQUENCE")
        print("=" * 60)

        try:
            # Step 1: Extended diagnostic session
            self.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
            time.sleep(0.5)

            # Step 2: Security access
            TESLA_ACCESS_LEVEL = 0x11
            retry_count = 0
            max_retries = 5

            while retry_count < max_retries:
                try:
                    seed = self.security_access(TESLA_ACCESS_LEVEL)
                    print(f"🌱 Security seed: {hexlify(seed).decode()}")

                    key = self.tesla_radar_security_algorithm(seed)
                    print(f"🔑 Security key: {hexlify(key).decode()}")

                    self.security_access(TESLA_ACCESS_LEVEL + 1, key)
                    print("✅ Security access successful!")
                    break

                except NegativeResponseError as e:
                    if e.error_code == 0x37:  # Required time delay not expired
                        print("⏳ Security access rate limited, waiting...")
                        time.sleep(1)
                        retry_count += 1
                        continue
                    else:
                        raise

            if retry_count >= max_retries:
                print("❌ Security access failed after max retries")
                return False

            # Step 3: Read current VIN (optional)
            try:
                vin = self.read_data_by_identifier(DATA_IDENTIFIER_TYPE.VIN)
                print(f"📋 Current VIN: {vin.decode().strip()}")
            except Exception as e:
                print(f"⚠️  Could not read VIN: {e}")

            # Step 4: ECU RESET - This is the key!
            print("\n🎯 PERFORMING ECU RESET - THIS SHOULD TRIGGER PLANT MODE EXIT!")
            self.ecu_reset(RESET_TYPE.SOFT)
            print("✅ ECU reset command sent!")

            return True

        except Exception as e:
            print(f"❌ UDS sequence failed: {e}")
            return False

    def run_reset_sequence(self):
        """Run the complete reset sequence"""
        print("🔧 Tesla Radar UDS Reset Tool")
        print("Attempting to trigger plant mode exit via ECU reset...")
        print()

        if not self.setup_can():
            return False

        self.start_isotp_thread()
        time.sleep(1)  # Allow ISOTP thread to start

        success = self.perform_uds_reset_sequence()

        if success:
            print("\n🎉 UDS RESET SEQUENCE COMPLETED!")
            print("🔍 Now monitor CAN bus for:")
            print("   - 0x631 initialization message")
            print("   - Radar returning to normal operation")
            print("   - Plant mode exit confirmation")
        else:
            print("\n❌ UDS RESET SEQUENCE FAILED!")

        # Keep monitoring for a bit
        print("\n👂 Monitoring for radar response...")
        time.sleep(5)

        self.running = False
        return success

    def cleanup(self):
        """Cleanup resources"""
        self.running = False
        if self.bus:
            self.bus.shutdown()


def main():
    """Main function"""
    reset_tool = TeslaRadarUDSReset("can1")

    try:
        success = reset_tool.run_reset_sequence()

        if success:
            print("\n🎯 NEXT STEPS:")
            print("   Run radar_troubleshoot.py to check if 0x631 appears")
            print("   The radar should now be ready for Tesla protocol")
        else:
            print("\n❌ Reset failed - radar may need hardware power cycle")

    except KeyboardInterrupt:
        print("\n⚠️ UDS reset interrupted by user")
    except Exception as e:
        print(f"\n❌ UDS reset failed: {e}")
    finally:
        reset_tool.cleanup()


if __name__ == "__main__":
    main()
