#!/usr/bin/env python3
"""
Tesla Radar Troubleshooting Script
==================================

This script helps diagnose why the Tesla radar isn't activating properly.
It performs step-by-step diagnostics to identify the root cause.
"""

import argparse
import can
import time
import struct
import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from tesla_radar_protocol import setup_can


@dataclass
class RadarDiagnostic:
    """Diagnostic results for radar troubleshooting"""

    can_interface_working: bool = False
    radar_responding: bool = False
    initialization_detected: bool = False
    vin_transmission_working: bool = False
    message_frequencies_correct: bool = False
    plant_mode_exit: bool = False
    scan_index_dynamic: bool = False

    def overall_status(self) -> str:
        """Get overall diagnostic status"""
        if self.scan_index_dynamic:
            return "✅ RADAR FULLY WORKING"
        elif self.radar_responding:
            return "⚠️ RADAR RESPONDING BUT NOT ACTIVE"
        elif self.can_interface_working:
            return "❌ CAN WORKING BUT RADAR NOT RESPONDING"
        else:
            return "❌ CAN INTERFACE FAILURE"


class TeslaRadarTroubleshooter:
    """Tesla Radar Troubleshooting Tool"""

    def __init__(self, can_interface: str = "can1", debug: bool = False):
        self.can_interface = can_interface
        self.bus = None
        self.running = False
        self.diagnostic = RadarDiagnostic()
        self.debug = debug

        # Message tracking
        self.received_messages = defaultdict(int)
        self.message_timestamps = defaultdict(list)
        self.radar_responses = []
        self.scan_indices = deque(maxlen=20)
        self.vin_cycles = 0

        # Tesla protocol messages
        self.tesla_messages = {
            0x199: {"name": "DI_state", "freq": 100, "data": None},
            0x169: {"name": "DI_torque2", "freq": 100, "data": None},
            0x119: {"name": "DI_torque1", "freq": 100, "data": None},
            0x109: {"name": "DI_speed", "freq": 100, "data": None},
            0x159: {"name": "DI_radVehicleState", "freq": 50, "data": None},
            0x149: {"name": "DI_boundaries", "freq": 50, "data": None},
            0x129: {"name": "DI_digital", "freq": 50, "data": None},
            0x1A9: {"name": "DI_torqueMotor", "freq": 50, "data": None},
            0x209: {"name": "DI_config", "freq": 10, "data": None},
            0x219: {"name": "DI_aebLimitations", "freq": 10, "data": None},
            0x2B9: {"name": "DI_vinString", "freq": 4, "data": None},
            0x2A9: {"name": "radarState", "freq": 1, "data": None},
            0x2D9: {"name": "DI_radarConfig", "freq": 1, "data": None},
        }

        # VIN for testing
        self.vin = "5YJSB7E43GF113105"

    def setup_can(self) -> bool:
        """Setup CAN interface"""
        try:
            self.bus = setup_can(interface=self.can_interface)
            self.diagnostic.can_interface_working = True
            print(f"✅ CAN interface {self.can_interface} setup successful")
            return True
        except Exception as e:
            print(f"❌ CAN interface setup failed: {e}")
            return False

    def generate_tesla_message(self, msg_id: int, counter: int) -> bytes:
        """Generate Tesla protocol message"""
        if msg_id == 0x199:  # DI_state
            return struct.pack(
                "<BBBBBBBB", 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        elif msg_id == 0x169:  # DI_torque2
            return struct.pack(
                "<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        elif msg_id == 0x119:  # DI_torque1
            return struct.pack(
                "<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        elif msg_id == 0x109:  # DI_speed (30 km/h)
            return struct.pack(
                "<BBBBBBBB", 0x1E, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        elif msg_id == 0x159:  # DI_radVehicleState
            return struct.pack(
                "<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        elif msg_id == 0x149:  # DI_boundaries
            return struct.pack(
                "<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        elif msg_id == 0x129:  # DI_digital
            return struct.pack(
                "<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        elif msg_id == 0x1A9:  # DI_torqueMotor
            return struct.pack(
                "<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        elif msg_id == 0x209:  # DI_config
            return struct.pack(
                "<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        elif msg_id == 0x219:  # DI_aebLimitations
            return struct.pack(
                "<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        elif msg_id == 0x2B9:  # DI_vinString (3-part VIN transmission)
            cycle = (counter // 4) % 3
            if cycle == 0:
                # First part: characters 0-2
                data = [0x10] + [ord(c) for c in self.vin[0:3]] + [0x00] * 4
            elif cycle == 1:
                # Second part: characters 3-9
                data = [0x11] + [ord(c) for c in self.vin[3:10]] + [0x00] * 0
            else:
                # Third part: characters 10-16
                data = [0x12] + [ord(c) for c in self.vin[10:17]] + [0x00] * 0
            return bytes(data[:8])
        elif msg_id == 0x2A9:  # radarState
            radar_position = 0  # Front center
            radar_epas_type = 0  # Bosch L538
            return struct.pack(
                "<BBBBBBBB",
                radar_position,
                radar_epas_type,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            )
        elif msg_id == 0x2D9:  # DI_radarConfig
            return struct.pack(
                "<BBBBBBBB", 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
        else:
            return bytes(8)

    def send_tesla_protocol(self, duration: int = 10):
        """Send Tesla protocol messages"""
        print(f"🚀 Starting Tesla protocol transmission for {duration} seconds...")

        start_time = time.time()
        counter = 0

        while self.running and (time.time() - start_time) < duration:
            current_time = time.time()

            # Send messages at their required frequencies
            for msg_id, config in self.tesla_messages.items():
                freq = config["freq"]
                interval = 1.0 / freq

                # Check if it's time to send this message
                if (
                    len(self.message_timestamps[msg_id]) == 0
                    or (current_time - self.message_timestamps[msg_id][-1]) >= interval
                ):

                    try:
                        data = self.generate_tesla_message(msg_id, counter)
                        msg = can.Message(
                            arbitration_id=msg_id, data=data, is_extended_id=False
                        )
                        self.bus.send(msg)
                        self.message_timestamps[msg_id].append(current_time)
                    except Exception as e:
                        print(f"❌ Failed to send message {msg_id:03X}: {e}")

            counter += 1
            time.sleep(0.001)  # 1ms loop

    def monitor_radar_responses(self):
        """Monitor radar responses"""
        print("👂 Monitoring radar responses...")

        while self.running:
            try:
                message = self.bus.recv(timeout=0.1)
                if message:
                    self.received_messages[message.arbitration_id] += 1

                    # Check for radar responses
                    if message.arbitration_id == 0x300:
                        self.diagnostic.radar_responding = True
                        self.radar_responses.append(message)

                        # Parse scan index
                        if len(message.data) >= 2:
                            scan_index = message.data[0]
                            self.scan_indices.append(scan_index)

                            # Check if scan index is dynamic
                            if len(self.scan_indices) >= 10:
                                unique_indices = len(set(self.scan_indices))
                                if unique_indices > 1:
                                    self.diagnostic.scan_index_dynamic = True

                        if self.debug:
                            print(f"📡 Radar response 0x300: {message.data.hex()}")

                    elif message.arbitration_id == 0x631:
                        self.diagnostic.initialization_detected = True
                        if self.debug:
                            print(
                                f"🔄 Radar initialization 0x631: {message.data.hex()}"
                            )

                    # Other radar messages
                    elif message.arbitration_id in range(0x360, 0x380) and self.debug:
                        print(
                            f"📊 Radar data {message.arbitration_id:03X}: {message.data.hex()}"
                        )

            except Exception as e:
                if self.running:
                    print(f"❌ Receive error: {e}")
                break

    def analyze_message_frequencies(self):
        """Analyze message transmission frequencies"""
        print("\n📊 MESSAGE FREQUENCY ANALYSIS:")

        for msg_id, config in self.tesla_messages.items():
            timestamps = self.message_timestamps[msg_id]
            expected_freq = config["freq"]

            if len(timestamps) >= 2:
                intervals = [
                    timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))
                ]
                avg_interval = sum(intervals) / len(intervals)
                actual_freq = 1.0 / avg_interval if avg_interval > 0 else 0

                status = (
                    "✅"
                    if abs(actual_freq - expected_freq) < (expected_freq * 0.1)
                    else "❌"
                )
                print(
                    f"   {msg_id:03X} ({config['name']}): {actual_freq:.1f}Hz (expected {expected_freq}Hz) {status}"
                )
            else:
                print(f"   {msg_id:03X} ({config['name']}): No messages sent ❌")

    def analyze_vin_transmission(self):
        """Analyze VIN transmission"""
        print("\n🆔 VIN TRANSMISSION ANALYSIS:")

        vin_timestamps = self.message_timestamps.get(0x2B9, [])
        if len(vin_timestamps) >= 12:  # At least 4 cycles (3 parts each)
            self.vin_cycles = len(vin_timestamps) // 3
            self.diagnostic.vin_transmission_working = self.vin_cycles >= 7

            status = "✅" if self.diagnostic.vin_transmission_working else "⚠️"
            print(f"   VIN cycles completed: {self.vin_cycles}/7 {status}")
            print(f"   VIN being transmitted: {self.vin}")
        else:
            print(
                f"   VIN transmission incomplete: {len(vin_timestamps)} messages sent ❌"
            )

    def analyze_radar_responses(self):
        """Analyze radar responses"""
        print("\n🎯 RADAR RESPONSE ANALYSIS:")

        if self.diagnostic.radar_responding:
            print(f"   Radar responding: ✅ ({len(self.radar_responses)} messages)")

            if self.scan_indices:
                unique_indices = len(set(self.scan_indices))
                last_index = self.scan_indices[-1]

                if unique_indices > 1:
                    print(f"   Scan index: DYNAMIC ✅ ({unique_indices} unique values)")
                else:
                    print(f"   Scan index: STATIC ❌ (stuck at {last_index})")
            else:
                print("   No scan index data available ❌")
        else:
            print("   Radar not responding ❌")

        if self.diagnostic.initialization_detected:
            print("   Initialization detected: ✅")
        else:
            print("   Initialization detected: ❌")

    def run_diagnostic(self, duration: int = 30):
        """Run complete diagnostic"""
        print("🔍 TESLA RADAR TROUBLESHOOTING")
        print("=" * 50)

        # Step 1: Setup CAN
        if not self.setup_can():
            return self.diagnostic

        # Step 2: Start monitoring
        self.running = True
        monitor_thread = threading.Thread(target=self.monitor_radar_responses)
        monitor_thread.daemon = True
        monitor_thread.start()

        # Step 3: Send Tesla protocol
        protocol_thread = threading.Thread(
            target=self.send_tesla_protocol, args=(duration,)
        )
        protocol_thread.daemon = True
        protocol_thread.start()

        # Step 4: Wait for completion
        time.sleep(duration)
        self.running = False

        # Step 5: Analyze results
        print("\n🔍 DIAGNOSTIC RESULTS:")
        print("=" * 50)

        self.analyze_message_frequencies()
        self.analyze_vin_transmission()
        self.analyze_radar_responses()

        # Step 6: Overall status
        print(f"\n📊 OVERALL STATUS: {self.diagnostic.overall_status()}")

        # Step 7: Recommendations
        self.provide_recommendations()

        return self.diagnostic

    def provide_recommendations(self):
        """Provide troubleshooting recommendations"""
        print("\n💡 RECOMMENDATIONS:")
        print("=" * 30)

        if not self.diagnostic.radar_responding:
            print("1. ❌ Radar not responding - Check:")
            print("   - Radar power supply (12V)")
            print("   - CAN wiring and termination")
            print("   - Try different CAN interface (can0)")
            print("   - Check radar ground connections")

        elif not self.diagnostic.initialization_detected:
            print("2. ❌ No initialization detected - Try:")
            print("   - Power cycle the radar")
            print("   - Check for 0x631 message requirement")
            print("   - Verify radar expects specific init sequence")

        elif not self.diagnostic.vin_transmission_working:
            print("3. ❌ VIN transmission incomplete - Check:")
            print("   - VIN format (17 characters)")
            print("   - Message timing (4Hz)")
            print("   - 3-part transmission sequence")

        elif not self.diagnostic.scan_index_dynamic:
            print("4. ❌ Scan index static - This is your main issue!")
            print("   - All Tesla messages are being sent correctly")
            print("   - Radar is responding but not scanning")
            print("   - May need additional activation sequence")
            print("   - Check if radar needs calibration/alignment")
            print("   - Verify AWD detection from VIN")

        else:
            print("✅ All diagnostics passed - Radar should be working!")

    def cleanup(self):
        """Cleanup resources"""
        self.running = False
        if self.bus:
            self.bus.shutdown()


def main():
    """Main troubleshooting function"""
    parser = argparse.ArgumentParser(description="Tesla radar troubleshooting tool")
    parser.add_argument(
        "interface",
        nargs="?",
        default="can1",
        help="CAN interface name (default: can1)",
    )
    parser.add_argument(
        "duration",
        nargs="?",
        type=int,
        default=30,
        help="Test duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose logging of CAN traffic",
    )

    args = parser.parse_args()

    print("🔧 Tesla Radar Troubleshooting Tool")
    print(f"   CAN Interface: {args.interface}")
    print(f"   Test Duration: {args.duration} seconds")
    print("   VIN: 5YJSB7E43GF113105")
    if args.debug:
        print("   Debug: enabled")
    print()

    troubleshooter = TeslaRadarTroubleshooter(args.interface, debug=args.debug)

    try:
        diagnostic = troubleshooter.run_diagnostic(args.duration)

        print("\n🎯 NEXT STEPS:")
        if diagnostic.scan_index_dynamic:
            print("   Radar is fully working! 🎉")
        elif diagnostic.radar_responding:
            print(
                "   Focus on activation sequence - the radar is responding but not scanning"
            )
        else:
            print("   Fix basic connectivity issues first")

    except KeyboardInterrupt:
        print("\n⚠️ Diagnostic interrupted by user")
    except Exception as e:
        print(f"\n❌ Diagnostic failed: {e}")
    finally:
        troubleshooter.cleanup()


if __name__ == "__main__":
    main()
