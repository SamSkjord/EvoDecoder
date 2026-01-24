#!/usr/bin/env python3
"""
Tesla Vehicle CAN Emulator
===========================

Emulates the Tesla vehicle CAN messages that the radar expects to see
to trigger full activation. Based on OpenPilot's safety_teslaradar.h

This should trigger the radar to send 0x631 and fully activate.
"""

import can
import time
import struct
from threading import Thread
import signal
import sys


class TeslaVehicleCANEmulator:
    """Emulates Tesla vehicle CAN messages for radar activation"""

    def __init__(self, can_interface: str = "can1"):
        self.can_interface = can_interface
        self.bus = None
        self.running = False
        self.counter = 0
        self.speed_kph = 0  # Vehicle speed in km/h
        self.radar_vin = "5YJSB7E43GF113105"  # Our extracted VIN

        # Message counters (from safety_teslaradar.h)
        self.x199_id = 0
        self.x169_id = 0
        self.x119_id = 0
        self.x109_id = 0
        self.x159_id = 0
        self.x149_id = 0
        self.x129_id = 0
        self.x1A9_id = 0
        self.x219_id = 0
        self.x2B9_id = 0

        # Radar configuration
        self.radar_position = 0  # 0=front, 1=rear
        self.radar_epas_type = 0

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

    def tesla_crc8(self, data: bytes) -> int:
        """Calculate Tesla CRC8 (from safety_teslaradar.h)"""
        crc_lookup = [
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

        crc = 0xFF
        for byte in data:
            crc = crc_lookup[crc ^ byte]
        return crc ^ 0xFF

    def tesla_checksum(self, data: bytes, msg_id: int) -> int:
        """Calculate Tesla checksum (from safety_teslaradar.h)"""
        cksm = (msg_id & 0xFF) + ((msg_id >> 8) & 0xFF)
        for byte in data:
            cksm = (cksm + byte) & 0xFF
        return cksm

    def send_can_message(self, msg_id: int, data: bytes):
        """Send CAN message"""
        try:
            msg = can.Message(arbitration_id=msg_id, data=data, is_extended_id=False)
            self.bus.send(msg)
        except Exception as e:
            print(f"❌ Failed to send CAN message {msg_id:03X}: {e}")

    def send_100hz_messages(self):
        """Send 100Hz messages (0x199, 0x169, 0x119, 0x109)"""
        # 0x199 message
        data = struct.pack("<I", 0x00207D2F) + bytes(
            [0x04, 0xFF, 0x00, self.x199_id << 4]
        )
        crc = self.tesla_crc8(data[:7])
        data = data[:7] + bytes([crc])
        self.send_can_message(0x199, data)
        self.x199_id = (self.x199_id + 1) % 16

        # 0x169 message (vehicle speed)
        speed_raw = int(self.speed_kph / 0.04) & 0x1FFF
        data = struct.pack("<I", speed_raw | (speed_raw << 13) | (speed_raw << 26))
        data += struct.pack(
            "<I",
            ((speed_raw >> 6) | (speed_raw << 7) | (self.x169_id << 20)) & 0x00FFFFFF,
        )
        cksm = self.tesla_checksum(data[:7], 0x169)
        data = data[:7] + bytes([cksm])
        self.send_can_message(0x169, data)
        self.x169_id = (self.x169_id + 1) % 16

        # 0x119 message
        data = struct.pack("<I", 0x11F41FFF) + bytes([0x80, self.x119_id])
        cksm = self.tesla_checksum(data[:5], 0x119)
        data = data[:5] + bytes([cksm])
        self.send_can_message(0x119, data)
        self.x119_id = (self.x119_id + 1) % 16

        # 0x109 message
        data = struct.pack("<I", 0x80000000 | (self.x109_id << 13)) + bytes(
            [0x00, 0x00, 0x00]
        )
        cksm = self.tesla_checksum(data[:7], 0x109)
        data = data[:7] + bytes([cksm])
        self.send_can_message(0x109, data)
        self.x109_id = (self.x109_id + 1) % 8

    def send_50hz_messages(self):
        """Send 50Hz messages (0x159, 0x149, 0x129, 0x1A9)"""
        # 0x159 message
        data = struct.pack("<I", 0x004FFFFB) + bytes(
            [0xFF, 0x07, 0x00, self.x159_id << 4]
        )
        cksm = self.tesla_checksum(data[:7], 0x159)
        data = data[:3] + bytes([cksm]) + data[4:]
        self.send_can_message(0x159, data)
        self.x159_id = (self.x159_id + 1) % 16

        # 0x149 message
        data = struct.pack("<I", 0x6A022600) + bytes(
            [0xAA, 0x04, 0x0F, self.x149_id << 4]
        )
        cksm = self.tesla_checksum(data[:7], 0x149)
        data = data[:7] + bytes([cksm])
        self.send_can_message(0x149, data)
        self.x149_id = (self.x149_id + 1) % 16

        # 0x129 message
        data = struct.pack("<I", 0x20000000) + bytes([self.x129_id << 4])
        cksm = self.tesla_checksum(data[:5], 0x129)
        data = data[:5] + bytes([cksm])
        self.send_can_message(0x129, data)
        self.x129_id = (self.x129_id + 1) % 16

        # 0x1A9 message
        data = struct.pack("<I", 0x000C0000 | (self.x1A9_id << 28)) + bytes([0x00])
        cksm = self.tesla_checksum(data[:4], 0x1A9)
        data = data[:4] + bytes([cksm])
        self.send_can_message(0x1A9, data)
        self.x1A9_id = (self.x1A9_id + 1) % 16

    def send_10hz_messages(self):
        """Send 10Hz messages (0x209, 0x219)"""
        # 0x209 message
        data = struct.pack("<II", 0x5294FF00, 0x00800313)
        self.send_can_message(0x209, data)

        # 0x219 message
        data = struct.pack("<I", 0x00000000) + bytes([0x00, 0x00, self.x219_id << 4])
        crc = self.tesla_crc8(data[:7])
        data = data[:7] + bytes([crc])
        self.send_can_message(0x219, data)
        self.x219_id = (self.x219_id + 1) % 16

    def send_4hz_messages(self):
        """Send 4Hz messages (0x2B9 - VIN) - SIMPLIFIED"""
        # Skip VIN message for now - causing transmission errors
        # Focus on essential messages first
        pass

    def send_1hz_messages(self):
        """Send 1Hz messages (0x2A9, 0x2D9)"""
        # 0x2A9 message
        data = struct.pack("<I", 0x41431642)
        config = 0x10020000 | (self.radar_position << 4) | (self.radar_epas_type << 12)

        # Check if dual motor (position 8 of VIN is '2')
        if len(self.radar_vin) >= 8 and self.radar_vin[7] == "2":
            data = struct.pack("<I", 0x41431642 | 0x08)  # Set AWD bit

        data += struct.pack("<I", config)
        self.send_can_message(0x2A9, data)

        # 0x2D9 message
        data = struct.pack("<II", 0x00834080, 0x00000000)
        self.send_can_message(0x2D9, data)

    def send_trigger_message(self):
        """Send 0x17C trigger message to activate radar"""
        data = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        self.send_can_message(0x17C, data)

    def emulator_loop(self):
        """Main emulator loop"""
        print("🚀 Starting Tesla Vehicle CAN Emulator")
        print("🎯 Sending vehicle messages to trigger radar activation...")

        # Send initial trigger
        self.send_trigger_message()

        start_time = time.time()

        while self.running:
            # 100Hz messages (every 10ms)
            self.send_100hz_messages()

            # 50Hz messages (every 20ms)
            if self.counter % 2 == 0:
                self.send_50hz_messages()

            # 10Hz messages (every 100ms)
            if self.counter % 10 == 0:
                self.send_10hz_messages()

            # 4Hz messages (every 250ms)
            if self.counter % 25 == 0:
                self.send_4hz_messages()

            # 1Hz messages (every 1000ms)
            if self.counter % 100 == 0:
                self.send_1hz_messages()

                # Send trigger message every second
                self.send_trigger_message()

                # Status update
                elapsed = time.time() - start_time
                print(f"📡 Running for {elapsed:.1f}s - Counter: {self.counter}")

            self.counter = (self.counter + 1) % 100

            # 100Hz = 10ms delay
            time.sleep(0.01)

    def run(self):
        """Start the emulator"""
        if not self.setup_can():
            return False

        self.running = True

        def signal_handler(sig, frame):
            print("\n🛑 Stopping Tesla Vehicle CAN Emulator...")
            self.running = False
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        try:
            self.emulator_loop()
        except Exception as e:
            print(f"❌ Emulator error: {e}")
        finally:
            if self.bus:
                self.bus.shutdown()

        return True


def main():
    """Main function"""
    emulator = TeslaVehicleCANEmulator("can1")

    print("🔧 Tesla Vehicle CAN Emulator")
    print("=" * 50)
    print("📋 This emulator sends Tesla vehicle CAN messages")
    print("   to trigger the radar to send 0x631 and fully activate")
    print("⚠️  Monitor CAN bus for 0x631 initialization message!")
    print()

    emulator.run()


if __name__ == "__main__":
    main()
