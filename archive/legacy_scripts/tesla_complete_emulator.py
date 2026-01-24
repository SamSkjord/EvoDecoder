#!/usr/bin/env python3
"""
Tesla Complete Vehicle Emulator
===============================

EXACT Tesla radar activation protocol from tesla_radar.h in past work/tesla_radar_protocol.py
This implementation WILL increase radar power draw and activate the radar!
"""

import can
import time
import signal
import sys


class TeslaCompleteEmulator:
    """Complete Tesla vehicle emulation using EXACT Tesla radar protocol"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None
        self.running = False
        self.speed_kph = 25  # Set realistic speed
        self.radar_vin = "5YJSB7E43GF113105"
        self.tesla_radar_counter = 0
        self.tesla_radar_trigger_message_id = 0x17C

        # Tesla radar state variables (from tesla_radar.h)
        self.tesla_radar_vin_complete = 7  # Set to complete
        self.tesla_radar_should_send = 1  # Enable sending
        self.radarPosition = 1  # Front radar position
        self.radarEpasType = 2  # EPAS type

        # Message counters (EXACT from tesla_radar.h)
        self.tesla_radar_x2B9_id = 0
        self.tesla_radar_x159_id = 0
        self.tesla_radar_x219_id = 0
        self.tesla_radar_x149_id = 0
        self.tesla_radar_x129_id = 0
        self.tesla_radar_x1A9_id = 0
        self.tesla_radar_x199_id = 0
        self.tesla_radar_x169_id = 0
        self.tesla_radar_x119_id = 0
        self.tesla_radar_x109_id = 0

        # CRC lookup table (from tesla_radar.h)
        self.crc_lookup = [
            0x00,
            0x1D,
            0x3A,
            0x27,
            0x74,
            0x69,
            0x4E,
            0x53,
            0xE8,
            0xF5,
            0xD2,
            0xCF,
            0x9C,
            0x81,
            0xA6,
            0xBB,
            0xCD,
            0xD0,
            0xF7,
            0xEA,
            0xB9,
            0xA4,
            0x83,
            0x9E,
            0x25,
            0x38,
            0x1F,
            0x02,
            0x51,
            0x4C,
            0x6B,
            0x76,
            0x87,
            0x9A,
            0xBD,
            0xA0,
            0xF3,
            0xEE,
            0xC9,
            0xD4,
            0x6F,
            0x72,
            0x55,
            0x48,
            0x1B,
            0x06,
            0x21,
            0x3C,
            0x4A,
            0x57,
            0x70,
            0x6D,
            0x3E,
            0x23,
            0x04,
            0x19,
            0xA2,
            0xBF,
            0x98,
            0x85,
            0xD6,
            0xCB,
            0xEC,
            0xF1,
            0x13,
            0x0E,
            0x29,
            0x34,
            0x67,
            0x7A,
            0x5D,
            0x40,
            0xFB,
            0xE6,
            0xC1,
            0xDC,
            0x8F,
            0x92,
            0xB5,
            0xA8,
            0xDE,
            0xC3,
            0xE4,
            0xF9,
            0xAA,
            0xB7,
            0x90,
            0x8D,
            0x36,
            0x2B,
            0x0C,
            0x11,
            0x42,
            0x5F,
            0x78,
            0x65,
            0x94,
            0x89,
            0xAE,
            0xB3,
            0xE0,
            0xFD,
            0xDA,
            0xC7,
            0x7C,
            0x61,
            0x46,
            0x5B,
            0x08,
            0x15,
            0x32,
            0x2F,
            0x59,
            0x44,
            0x63,
            0x7E,
            0x2D,
            0x30,
            0x17,
            0x0A,
            0xB1,
            0xAC,
            0x8B,
            0x96,
            0xC5,
            0xD8,
            0xFF,
            0xE2,
            0x26,
            0x3B,
            0x1C,
            0x01,
            0x52,
            0x4F,
            0x68,
            0x75,
            0xCE,
            0xD3,
            0xF4,
            0xE9,
            0xBA,
            0xA7,
            0x80,
            0x9D,
            0xEB,
            0xF6,
            0xD1,
            0xCC,
            0x9F,
            0x82,
            0xA5,
            0xB8,
            0x03,
            0x1E,
            0x39,
            0x24,
            0x77,
            0x6A,
            0x4D,
            0x50,
            0xA1,
            0xBC,
            0x9B,
            0x86,
            0xD5,
            0xC8,
            0xEF,
            0xF2,
            0x49,
            0x54,
            0x73,
            0x6E,
            0x3D,
            0x20,
            0x07,
            0x1A,
            0x6C,
            0x71,
            0x56,
            0x4B,
            0x18,
            0x05,
            0x22,
            0x3F,
            0x84,
            0x99,
            0xBE,
            0xA3,
            0xF0,
            0xED,
            0xCA,
            0xD7,
            0x35,
            0x28,
            0x0F,
            0x12,
            0x41,
            0x5C,
            0x7B,
            0x66,
            0xDD,
            0xC0,
            0xE7,
            0xFA,
            0xA9,
            0xB4,
            0x93,
            0x8E,
            0xF8,
            0xE5,
            0xC2,
            0xDF,
            0x8C,
            0x91,
            0xB6,
            0xAB,
            0x10,
            0x0D,
            0x2A,
            0x37,
            0x64,
            0x79,
            0x5E,
            0x43,
            0xB2,
            0xAF,
            0x88,
            0x95,
            0xC6,
            0xDB,
            0xFC,
            0xE1,
            0x5A,
            0x47,
            0x60,
            0x7D,
            0x2E,
            0x33,
            0x14,
            0x09,
            0x7F,
            0x62,
            0x45,
            0x58,
            0x0B,
            0x16,
            0x31,
            0x2C,
            0x97,
            0x8A,
            0xAD,
            0xB0,
            0xE3,
            0xFE,
            0xD9,
            0xC4,
        ]

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

    def add_tesla_crc(self, MLB, MHB, msg_len):
        """Calculate CRC8 using 1D poly, FF start, FF end"""
        crc = 0xFF
        for x in range(msg_len):
            if x <= 3:
                v = (MLB >> (x * 8)) & 0xFF
            else:
                v = (MHB >> ((x - 4) * 8)) & 0xFF
            crc = self.crc_lookup[crc ^ v]
        crc = crc ^ 0xFF
        return crc

    def add_tesla_cksm2(self, dl, dh, msg_id, msg_len):
        """Calculate Tesla checksum"""
        cksm = (0xFF & msg_id) + (0xFF & (msg_id >> 8))
        for x in range(msg_len):
            if x <= 3:
                v = (dl >> (x * 8)) & 0xFF
            else:
                v = (dh >> ((x - 4) * 8)) & 0xFF
            cksm = (cksm + v) & 0xFF
        return cksm

    def radar_VIN_char(self, pos, shift):
        """Get VIN character at position with shift"""
        if pos < len(self.radar_vin):
            return ord(self.radar_vin[pos]) << (shift * 8)
        return 0

    def send_fake_message(self, msg_addr, msg_len, data_lo, data_hi):
        """Send CAN message"""
        try:
            # Convert to 8-byte array
            data = []
            for i in range(8):
                if i < 4:
                    data.append((data_lo >> (i * 8)) & 0xFF)
                else:
                    data.append((data_hi >> ((i - 4) * 8)) & 0xFF)

            # Truncate to actual message length
            data = data[:msg_len]

            msg = can.Message(arbitration_id=msg_addr, data=data, is_extended_id=False)
            self.bus.send(msg)

        except Exception as e:
            print(f"❌ Error sending 0x{msg_addr:03X}: {e}")

    def activate_tesla_radar(self):
        """Main Tesla radar activation protocol (from tesla_radar.h)"""
        if (self.tesla_radar_vin_complete != 7) or (self.tesla_radar_should_send == 0):
            return

        # Send all messages at 100Hz

        # Send 0x199
        MLB = 0x00207D2F
        MHB = 0x0000FF04 + (self.tesla_radar_x199_id << 20)
        crc = self.add_tesla_crc(MLB, MHB, 7)
        MHB = MHB + (crc << 24)
        self.tesla_radar_x199_id = (self.tesla_radar_x199_id + 1) % 16
        self.send_fake_message(0x199, 8, MLB, MHB)

        # Send 0x169 (speed data - CRITICAL!)
        speed_kph = int(self.speed_kph / 0.04) & 0x1FFF
        MLB = (speed_kph | (speed_kph << 13) | (speed_kph << 26)) & 0xFFFFFFFF
        MHB = (
            (speed_kph >> 6) | (speed_kph << 7) | (self.tesla_radar_x169_id << 20)
        ) & 0x00FFFFFF
        cksm = self.add_tesla_cksm2(MLB, MHB, 0x76, 7)
        MHB = MHB + (cksm << 24)
        self.tesla_radar_x169_id = (self.tesla_radar_x169_id + 1) % 16
        self.send_fake_message(0x169, 8, MLB, MHB)

        # Send 0x119
        MLB = 0x11F41FFF
        MHB = 0x00000080 + self.tesla_radar_x119_id
        cksm = self.add_tesla_cksm2(MLB, MHB, 0x17, 5)
        MHB = MHB + (cksm << 8)
        self.tesla_radar_x119_id = (self.tesla_radar_x119_id + 1) % 16
        self.send_fake_message(0x119, 6, MLB, MHB)

        # Send 0x109
        MLB = 0x80000000 + (self.tesla_radar_x109_id << 13)
        MHB = 0x00
        cksm = self.add_tesla_cksm2(MLB, MHB, 0x7, 7)
        MHB = MHB + (cksm << 24)
        self.tesla_radar_x109_id = (self.tesla_radar_x109_id + 1) % 8
        self.send_fake_message(0x109, 8, MLB, MHB)

        # Send all messages at 50Hz
        if self.tesla_radar_counter % 2 == 0:
            # Send 0x159
            MLB = 0x004FFFFB
            MHB = 0x000007FF + (self.tesla_radar_x159_id << 12)
            cksm = self.add_tesla_cksm2(MLB, MHB, 0xC, 7)
            MLB = MLB + (cksm << 24)
            self.tesla_radar_x159_id = (self.tesla_radar_x159_id + 1) % 16
            self.send_fake_message(0x159, 8, MLB, MHB)

            # Send 0x149
            MLB = 0x6A022600
            MHB = 0x000F04AA + (self.tesla_radar_x149_id << 20)
            cksm = self.add_tesla_cksm2(MLB, MHB, 0x46, 7)
            MHB = MHB + (cksm << 24)
            self.tesla_radar_x149_id = (self.tesla_radar_x149_id + 1) % 16
            self.send_fake_message(0x149, 8, MLB, MHB)

            # Send 0x129
            MLB = 0x20000000
            MHB = 0x00 + (self.tesla_radar_x129_id << 4)
            cksm = self.add_tesla_cksm2(MLB, MHB, 0x16, 5)
            MHB = MHB + (cksm << 8)
            self.tesla_radar_x129_id = (self.tesla_radar_x129_id + 1) % 16
            self.send_fake_message(0x129, 6, MLB, MHB)

            # Send 0x1A9
            MLB = 0x000C0000 + (self.tesla_radar_x1A9_id << 28)
            MHB = 0x00
            cksm = self.add_tesla_cksm2(MLB, MHB, 0x38, 4)
            MHB = MHB + cksm
            self.tesla_radar_x1A9_id = (self.tesla_radar_x1A9_id + 1) % 16
            self.send_fake_message(0x1A9, 5, MLB, MHB)

        # Send all messages at 10Hz
        if self.tesla_radar_counter % 10 == 0:
            # Send 0x209
            MLB = 0x5294FF00
            MHB = 0x00800313
            self.send_fake_message(0x209, 8, MLB, MHB)

            # Send 0x219
            MLB = 0x00000000
            MHB = 0x00000000
            MHB = MHB + (self.tesla_radar_x219_id << 20)
            crc = self.add_tesla_crc(MLB, MHB, 7)
            MHB = MHB + (crc << 24)
            self.tesla_radar_x219_id = (self.tesla_radar_x219_id + 1) % 16
            self.send_fake_message(0x219, 8, MLB, MHB)

        # Send all messages at 4Hz
        if self.tesla_radar_counter % 25 == 0:
            # Send 0x2B9 (VIN transmission)
            rec = 0x10 + self.tesla_radar_x2B9_id
            if rec == 0x10:
                MLB = 0x00000000 | rec
                MHB = (
                    self.radar_VIN_char(0, 1)
                    | self.radar_VIN_char(1, 2)
                    | self.radar_VIN_char(2, 3)
                )
            elif rec == 0x11:
                MLB = (
                    rec
                    | self.radar_VIN_char(3, 1)
                    | self.radar_VIN_char(4, 2)
                    | self.radar_VIN_char(5, 3)
                )
                MHB = (
                    self.radar_VIN_char(6, 0)
                    | self.radar_VIN_char(7, 1)
                    | self.radar_VIN_char(8, 2)
                    | self.radar_VIN_char(9, 3)
                )
            elif rec == 0x12:
                MLB = (
                    rec
                    | self.radar_VIN_char(10, 1)
                    | self.radar_VIN_char(11, 2)
                    | self.radar_VIN_char(12, 3)
                )
                MHB = (
                    self.radar_VIN_char(13, 0)
                    | self.radar_VIN_char(14, 1)
                    | self.radar_VIN_char(15, 2)
                    | self.radar_VIN_char(16, 3)
                )

            self.tesla_radar_x2B9_id = (self.tesla_radar_x2B9_id + 1) % 3
            self.send_fake_message(0x2B9, 8, MLB, MHB)

        # Send all messages at 1Hz
        if self.tesla_radar_counter == 0:
            # Send 0x2A9
            MLB = 0x41431642
            MHB = 0x10020000 | (self.radarPosition << 4) | (self.radarEpasType << 12)
            if len(self.radar_vin) >= 8 and self.radar_vin[7] == "2":
                # AWD if position 8 of VIN is a 2 (dual motor)
                MLB = MLB | 0x08
            self.send_fake_message(0x2A9, 8, MLB, MHB)

            # Send 0x2D9
            MLB = 0x00834080
            MHB = 0x00000000
            self.send_fake_message(0x2D9, 8, MLB, MHB)

        self.tesla_radar_counter = (self.tesla_radar_counter + 1) % 100

    def run(self):
        """Start the complete Tesla radar protocol"""
        if not self.setup_can():
            return False

        self.running = True

        def signal_handler(sig, frame):
            print("\n🛑 Stopping Tesla Complete Emulator...")
            self.running = False
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        print("🚗 Starting Tesla Radar Protocol...")
        print(f"   VIN: {self.radar_vin}")
        print(f"   Speed: {self.speed_kph} km/h")
        print(f"   Trigger: 0x{self.tesla_radar_trigger_message_id:03X}")
        print("   Sending complete Tesla message set with proper timing and checksums")
        print("   🎯 This WILL increase radar power draw!")
        print()

        # Send trigger message at 100Hz to activate protocol
        last_trigger = 0
        start_time = time.time()

        try:
            while self.running:
                current_time = time.time()

                # Send trigger message at 100Hz
                if current_time - last_trigger >= 0.01:  # 100Hz
                    # Send trigger message (simulates vehicle CAN message)
                    trigger_data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                    msg = can.Message(
                        arbitration_id=self.tesla_radar_trigger_message_id,
                        data=trigger_data,
                        is_extended_id=False,
                    )
                    self.bus.send(msg)

                    # This triggers the Tesla radar protocol
                    self.activate_tesla_radar()

                    last_trigger = current_time

                    # Status update every second
                    if (
                        int(current_time - start_time) > 0
                        and int(current_time - start_time) % 1 == 0
                    ):
                        elapsed = current_time - start_time
                        print(
                            f"📡 Tesla Protocol running for {elapsed:.1f}s - Counter: {self.tesla_radar_counter}"
                        )
                        print(f"   🎯 WATCH FOR RADAR POWER INCREASE!")

                time.sleep(0.001)  # 1ms loop

        except Exception as e:
            print(f"❌ Emulator error: {e}")
        finally:
            if self.bus:
                self.bus.shutdown()

        return True


def main():
    """Main function"""
    emulator = TeslaCompleteEmulator("can1")

    print("🔧 Tesla Complete Vehicle Emulator")
    print("=" * 50)
    print("🎯 EXACT Tesla radar protocol from tesla_radar.h")
    print("📡 This implementation WILL increase radar power draw!")
    print("⚡ Includes all Tesla messages with proper timing and checksums")
    print("⚠️  Monitor with radar_631_monitor.py for activation!")
    print()

    emulator.run()


if __name__ == "__main__":
    main()
