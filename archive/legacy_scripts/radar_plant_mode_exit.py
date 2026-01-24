#!/usr/bin/env python3
"""
Tesla Radar Plant Mode Exit
===========================

Final script to exit plant mode using the working UDS communication.
Based on successful UDS test and OpenPilot's VIN learning routine.
"""

import can
import time
import struct
from binascii import hexlify

DEBUG = True


class TeslaRadarPlantModeExit:
    """Tesla Radar Plant Mode Exit Tool"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None
        self.tx_addr = 0x641
        self.rx_addr = 0x651

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

    def send_uds_message(self, data: bytes, timeout: float = 3.0) -> bytes:
        """Send UDS message and wait for response"""
        if DEBUG:
            print(f"S: {self.tx_addr:03X} -> {hexlify(data).decode()}")

        # Send message
        msg = can.Message(arbitration_id=self.tx_addr, data=data, is_extended_id=False)
        self.bus.send(msg)

        # Wait for response
        start_time = time.time()
        while (time.time() - start_time) < timeout:
            message = self.bus.recv(timeout=0.1)
            if message and message.arbitration_id == self.rx_addr:
                if DEBUG:
                    print(
                        f"R: {message.arbitration_id:03X} -> {hexlify(message.data).decode()}"
                    )

                # Parse single frame response
                data = message.data
                if len(data) > 0 and (data[0] >> 4) == 0:  # Single frame
                    frame_size = data[0] & 0x0F
                    payload = data[1 : 1 + frame_size]
                    if DEBUG:
                        print(f"   Payload: {hexlify(payload).decode()}")
                    return payload

        raise Exception(f"Timeout waiting for UDS response (after {timeout}s)")

    def diagnostic_session_control(self, session_type: int):
        """UDS Diagnostic Session Control"""
        print(f"📋 Setting diagnostic session: {session_type}")
        msg = (
            struct.pack("BB", 0x02, 0x10) + struct.pack("B", session_type) + b"\x00" * 5
        )
        resp = self.send_uds_message(msg)

        if len(resp) == 0 or resp[0] != 0x50:
            raise Exception(
                f"Diagnostic session control failed: {hexlify(resp).decode()}"
            )

        print(f"✅ Session {session_type} confirmed")
        return resp

    def security_access_request_seed(self, level: int):
        """UDS Security Access - Request Seed"""
        print(f"🔒 Requesting security seed (level {level})")
        msg = struct.pack("BBB", 0x02, 0x27, level) + b"\x00" * 5
        resp = self.send_uds_message(msg)

        if len(resp) == 0 or resp[0] != 0x67:
            raise Exception(
                f"Security access request seed failed: {hexlify(resp).decode()}"
            )

        seed = resp[2:]  # Skip service ID and level
        print(f"🌱 Security seed: {hexlify(seed).decode()}")
        return seed

    def security_access_send_key(self, level: int, key: bytes):
        """UDS Security Access - Send Key"""
        print(f"🔑 Sending security key (level {level})")
        msg_data = struct.pack("BBB", 0x02 + len(key), 0x27, level) + key
        msg = msg_data.ljust(8, b"\x00")
        resp = self.send_uds_message(msg)

        if len(resp) == 0 or resp[0] != 0x67:
            raise Exception(
                f"Security access send key failed: {hexlify(resp).decode()}"
            )

        print("✅ Security access successful!")
        return resp

    def read_data_by_identifier(self, identifier: int):
        """UDS Read Data By Identifier"""
        print(f"📖 Reading data identifier {identifier:04X}")
        msg = struct.pack("BBH", 0x03, 0x22, identifier) + b"\x00" * 4
        resp = self.send_uds_message(msg)

        if len(resp) == 0 or resp[0] != 0x62:
            raise Exception(f"Read data by identifier failed: {hexlify(resp).decode()}")

        data = resp[3:]  # Skip service ID and identifier echo
        return data

    def routine_control(self, control_type: int, routine_id: int):
        """UDS Routine Control"""
        print(f"🔄 Routine control: {control_type} on routine {routine_id}")
        # Correct format: length + service + control_type + routine_id (big-endian)
        msg = (
            bytes([0x04, 0x31, control_type])
            + struct.pack(">H", routine_id)
            + b"\x00" * 3
        )
        resp = self.send_uds_message(msg, timeout=6.0)  # Longer timeout for routines

        if len(resp) == 0 or resp[0] != 0x71:
            raise Exception(f"Routine control failed: {hexlify(resp).decode()}")

        result = resp[3:]  # Skip service ID, control type, and routine ID
        print(f"✅ Routine result: {hexlify(result).decode()}")
        return result

    def tesla_radar_security_algorithm(self, seed: bytes) -> bytes:
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
            k32 = (seed_int & ~(0xFF << k4 & 0xFFFFFFFF)) << (
                0x20 - k4
            ) & 0xFFFFFFFF | (seed_int >> k4) & 0xFFFFFFFF
        else:
            k32 = (
                (~(0xFF << k4 & 0xFFFFFFFF) << (0x20 - k4)) & seed_int & 0xFFFFFFFF
            ) >> (0x20 - k4) & 0xFFFFFFFF | (seed_int << k4) & 0xFFFFFFFF

        k2 = (seed_int >> 4) & 2 | (seed_int >> 0x1F)

        if k2 == 0:
            key_int = k32 | seed_int
        elif k2 == 1:
            key_int = k32 & seed_int
        elif k2 == 2:
            key_int = k32 ^ seed_int
        else:
            key_int = k32

        return struct.pack("!I", key_int)

    def check_plant_mode_status(self) -> str:
        """Check current plant mode status"""
        print("\n🌱 CHECKING PLANT MODE STATUS")
        print("=" * 40)

        try:
            # Step 1: Default session
            self.diagnostic_session_control(1)
            time.sleep(0.1)

            # Step 2: Extended diagnostic session
            self.diagnostic_session_control(3)
            time.sleep(0.1)

            # Step 3: Read plant mode status
            plant_mode_data = self.read_data_by_identifier(0xA022)
            plant_mode_str = plant_mode_data.decode("utf-8", errors="ignore").strip()
            print(
                f"🌱 Plant mode: '{plant_mode_str}' [{hexlify(plant_mode_data).decode()}]"
            )

            # Step 4: Read VIN for context
            try:
                vin_data = self.read_data_by_identifier(0xF190)
                vin_str = vin_data.decode("utf-8", errors="ignore").strip()
                print(f"🆔 VIN: '{vin_str}'")
            except Exception as e:
                print(f"⚠️  Could not read VIN: {e}")

            return plant_mode_str

        except Exception as e:
            print(f"❌ Plant mode check failed: {e}")
            return None

    def exit_plant_mode(self):
        """Exit plant mode via VIN learning routine"""
        print("\n🚀 EXITING PLANT MODE VIA VIN LEARNING")
        print("=" * 50)

        try:
            # Step 1: Default session
            self.diagnostic_session_control(1)
            time.sleep(0.1)

            # Step 2: Extended diagnostic session
            self.diagnostic_session_control(3)
            time.sleep(0.1)

            # Step 3: Security access
            seed = self.security_access_request_seed(0x11)
            key = self.tesla_radar_security_algorithm(seed)
            print(f"🔑 Security key: {hexlify(key).decode()}")
            self.security_access_send_key(0x12, key)

            # Step 4: Start VIN learning routine (ID 2563)
            print("\n🔄 Starting VIN learning routine (ID 2563)...")
            start_result = self.routine_control(1, 2563)  # START

            # Step 5: Monitor during VIN learning for initialization
            print("⏳ Monitoring during VIN learning for radar initialization...")
            found_631_during_learning = False
            scan_index_changing = False

            start_time = time.time()
            while (time.time() - start_time) < 10:  # Monitor for 10 seconds
                try:
                    message = self.bus.recv(timeout=0.1)
                    if message and message.arbitration_id == 0x631:
                        print(
                            f"🎯 FOUND 0x631 DURING VIN LEARNING: {hexlify(message.data).decode()}"
                        )
                        found_631_during_learning = True
                        break  # Exit early if we see 0x631
                    elif message and message.arbitration_id == 0x300:
                        if len(message.data) >= 1:
                            scan_index = message.data[0]
                            if scan_index != 40:  # 40 is the static value we saw before
                                print(f"📡 0x300 scan index changing: {scan_index:02X}")
                                scan_index_changing = True
                except:
                    continue

            # Step 6: Try to get results (routine might have completed)
            print("📋 Getting VIN learning results...")
            try:
                final_result = self.routine_control(3, 2563)  # REQUEST_RESULTS
                print(
                    f"✅ VIN learning completed with result: {hexlify(final_result).decode()}"
                )
            except Exception as e:
                print(f"⚠️  Could not get VIN learning results: {e}")
                # Try to stop if still running
                try:
                    print("⏹️  Attempting to stop VIN learning routine...")
                    stop_result = self.routine_control(2, 2563)  # STOP
                except Exception as e2:
                    print(f"⚠️  Could not stop VIN learning: {e2}")

            if found_631_during_learning:
                print("🎉 0x631 DETECTED DURING VIN LEARNING - RADAR INITIALIZED!")
            elif scan_index_changing:
                print("✅ Scan index is changing - radar may be activating!")
            else:
                print("⚠️  No clear initialization signs during VIN learning")

            print("✅ VIN learning sequence completed!")
            return True

        except Exception as e:
            print(f"❌ Plant mode exit failed: {e}")
            return False

    def monitor_for_631_initialization(self, duration: int = 10):
        """Monitor for 0x631 initialization message"""
        print(f"\n👂 MONITORING FOR 0x631 INITIALIZATION ({duration}s)")
        print("=" * 50)

        found_631 = False
        start_time = time.time()

        while (time.time() - start_time) < duration:
            try:
                message = self.bus.recv(timeout=0.1)
                if message and message.arbitration_id == 0x631:
                    print(
                        f"🎯 FOUND 0x631 INITIALIZATION: {hexlify(message.data).decode()}"
                    )
                    found_631 = True
                elif message and message.arbitration_id == 0x300:
                    # Check if scan index is changing
                    if len(message.data) >= 1:
                        scan_index = message.data[0]
                        print(f"📡 0x300 scan index: {scan_index:02X}")
            except:
                continue

        if found_631:
            print("✅ 0x631 initialization detected - radar should be active!")
        else:
            print("❌ No 0x631 initialization detected")

        return found_631

    def run_plant_mode_exit(self):
        """Run complete plant mode exit sequence"""
        print("🔧 Tesla Radar Plant Mode Exit Tool")
        print("=" * 50)

        if not self.setup_can():
            return False

        # Step 1: Assume radar is in plant mode and attempt VIN learning
        print("🎯 ATTEMPTING VIN LEARNING TO TRIGGER PLANT MODE EXIT...")
        print("   (Skipping plant mode check - going directly to VIN learning)")

        success = self.exit_plant_mode()

        if not success:
            print("❌ VIN learning failed")
            return False

        # Step 2: Try to check plant mode status after VIN learning
        print("\n🔍 Checking status after VIN learning...")
        try:
            final_plant_mode = self.check_plant_mode_status()
        except Exception as e:
            print(f"⚠️  Plant mode check still not supported: {e}")
            final_plant_mode = "unknown"

        # Step 4: Monitor for 0x631 initialization
        found_631 = self.monitor_for_631_initialization()

        # Step 5: Final status
        print("\n🎯 FINAL STATUS:")
        print("=" * 30)

        if final_plant_mode and "plant" not in final_plant_mode.lower():
            print("✅ Plant mode successfully exited!")
        else:
            print("⚠️  Plant mode status unclear")

        if found_631:
            print("✅ 0x631 initialization detected!")
            print("🎉 RADAR SHOULD NOW BE FULLY ACTIVE!")
        else:
            print("❌ No 0x631 initialization detected")
            print("   Try running radar_troubleshoot.py to check status")

        return found_631


def main():
    """Main function"""
    exit_tool = TeslaRadarPlantModeExit("can1")

    try:
        success = exit_tool.run_plant_mode_exit()

        if success:
            print("\n🎉 SUCCESS! Radar plant mode exit completed!")
            print("   Next: Run radar_troubleshoot.py to confirm active tracking")
        else:
            print("\n❌ Plant mode exit incomplete")
            print("   Check CAN connections and radar power")

    except KeyboardInterrupt:
        print("\n⚠️ Plant mode exit interrupted by user")
    except Exception as e:
        print(f"\n❌ Plant mode exit failed: {e}")
    finally:
        if exit_tool.bus:
            exit_tool.bus.shutdown()


if __name__ == "__main__":
    main()
