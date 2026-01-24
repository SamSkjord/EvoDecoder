#!/usr/bin/env python3
"""
Tesla Radar Activator - Complete Implementation
Based on working Panda safety layer implementation
Combines proper Tesla protocol with comprehensive monitoring
"""

import os
import can
import time
import threading
import argparse
from tesla_radar_protocol import TeslaRadarProtocol, setup_can


class TeslaRadarActivator:
    """Complete Tesla Radar Activation System"""

    def __init__(self, can_bus, vin="5YJSB7E43GF113105", debug=False):
        self.can_bus = can_bus
        self.debug = debug
        self.running = False

        # Initialize Tesla protocol
        self.protocol = TeslaRadarProtocol(can_bus, vin=vin, debug=debug)

        # Monitoring state
        self.scan_indices = []
        self.power_levels = []
        self.error_codes = set()
        self.valid_objects = 0
        self.paired_messages = 0
        self.init_631_count = 0
        self.status_300_count = 0

        # Success tracking
        self.plant_mode_exited = False
        self.radar_fully_active = False
        self.dynamic_scanning = False

        # Statistics
        self.start_time = time.time()
        self.last_status_update = time.time()
        self.message_stats = {}

    def monitor_radar_behavior(self):
        """Enhanced radar monitoring with OpenPilot-style validation"""
        print("👁️  Starting enhanced radar monitoring...")

        while self.running:
            try:
                msg = self.can_bus.recv(timeout=0.1)
            except (ValueError, IndexError) as err:
                if self.debug:
                    print(f"CAN decode error: {err}")
                continue
            except can.CanError as err:
                if self.debug:
                    print(f"CAN error: {err}")
                continue
            if msg is not None:
                msg_id = msg.arbitration_id

                # Track message statistics
                if msg_id not in self.message_stats:
                    self.message_stats[msg_id] = {
                        "count": 0,
                        "last_data": None,
                        "changes": 0,
                    }

                self.message_stats[msg_id]["count"] += 1

                # Track data changes
                if self.message_stats[msg_id]["last_data"] != msg.data:
                    self.message_stats[msg_id]["changes"] += 1
                    self.message_stats[msg_id]["last_data"] = msg.data[:]

                # Critical radar messages
                if msg_id == 0x631:
                    self.init_631_count += 1
                    if self.debug:
                        print(
                            f"🔄 RADAR INIT (0x631) #{self.init_631_count}: {msg.data.hex()}"
                        )

                elif msg_id == 0x300:
                    self.status_300_count += 1
                    if len(msg.data) >= 8:
                        radar_state = msg.data[0] & 0x0F
                        scan_index = msg.data[1]
                        power_level = msg.data[2]

                        self.scan_indices.append(scan_index)
                        self.power_levels.append(power_level)

                        if self.debug:
                            print(
                                f"🎯 RADAR STATUS (0x300): State={radar_state}, "
                                f"Scan={scan_index}, Power={power_level}"
                            )

                elif msg_id == 0x3FF:
                    if len(msg.data) >= 2:
                        error_code = msg.data[1]
                        if error_code != 0:
                            self.error_codes.add(error_code)
                            if self.debug:
                                print(f"⚠️  ERROR CODE (0x3FF): {error_code}")

                # Monitor object tracking messages (0x310-0x36F)
                elif 0x310 <= msg_id <= 0x36F:
                    self.analyze_object_message(msg_id, msg.data)

            # Update status periodically
            if time.time() - self.last_status_update >= 5.0:
                self.update_status()
                self.last_status_update = time.time()

    def analyze_object_message(self, msg_id, data):
        """Analyze object tracking messages for valid data"""
        if len(data) < 8:
            return

        # Check for paired messages (A and B)
        if msg_id % 3 == 0:  # A message
            # Look for corresponding B message
            b_msg_id = msg_id + 1
            if b_msg_id in self.message_stats:
                self.paired_messages += 1

                # Extract basic object data
                raw_distance = (data[1] << 8) | data[0]
                distance = raw_distance * 0.1

                # Check for valid object (non-zero distance, reasonable range)
                if 0.5 < distance < 250:
                    self.valid_objects += 1
                    if self.debug and self.valid_objects % 10 == 0:
                        print(f"📊 Valid objects detected: {self.valid_objects}")

    def update_status(self):
        """Update and analyze radar status"""
        elapsed = time.time() - self.start_time

        # Sync counts with protocol-level monitoring to avoid missed frames
        self.init_631_count = max(
            self.init_631_count, getattr(self.protocol, "init_message_count", 0)
        )
        self.status_300_count = max(
            self.status_300_count, getattr(self.protocol, "status_message_count", 0)
        )

        # Analyze scan index behavior
        if len(self.scan_indices) > 10:
            unique_indices = set(self.scan_indices[-50:])  # Last 50 readings
            scan_range = max(self.scan_indices[-50:]) - min(self.scan_indices[-50:])

            if len(unique_indices) > 5 and scan_range > 10:
                if not self.dynamic_scanning:
                    self.dynamic_scanning = True
                    print("🎉 DYNAMIC SCANNING DETECTED! Radar is actively scanning!")

        # Check for plant mode exit
        if self.protocol.tesla_radar_status == 2 and not self.plant_mode_exited:
            self.plant_mode_exited = True
            print("🚀 PLANT MODE EXITED! Radar transitioned to active state!")

        # Check for full activation
        if (
            self.plant_mode_exited
            and self.protocol.tesla_radar_vin_complete >= 7
            and self.dynamic_scanning
            and self.valid_objects > 0
        ):
            if not self.radar_fully_active:
                self.radar_fully_active = True
                print("🎯 RADAR FULLY ACTIVE! All systems operational!")

        # Status report
        status_names = {0: "Not Present", 1: "Initializing", 2: "Active"}
        power_avg = (
            sum(self.power_levels[-10:]) / len(self.power_levels[-10:])
            if self.power_levels
            else 0
        )

        print(f"\n📊 STATUS UPDATE ({elapsed:.1f}s):")
        print(f"   Radar State: {status_names[self.protocol.tesla_radar_status]}")
        print(f"   VIN Complete: {self.protocol.tesla_radar_vin_complete}/7")
        print(f"   Init Messages: {self.init_631_count}")
        print(f"   Power Level: {power_avg:.1f}")
        print(f"   Scan Indices: {len(set(self.scan_indices[-20:]))} unique (last 20)")
        print(f"   Valid Objects: {self.valid_objects}")
        print(f"   Error Codes: {len(self.error_codes)}")
        if getattr(self.protocol, "error_code_counts", None):
            total_errors = sum(self.protocol.error_code_counts.values())
            print(
                f"   System Status Errors (0x3FF): {len(self.protocol.error_code_counts)} unique / {total_errors} total"
            )
            top_codes = sorted(
                self.protocol.error_code_counts.items(),
                key=lambda item: item[1],
                reverse=True,
            )[:5]
            if top_codes:
                formatted = ", ".join(
                    f"{code}:{count} ({self.protocol.describe_error_code(code)})"
                    for code, count in top_codes
                )
                print(f"   Top error codes: {formatted}")
        print(f"   Plant Mode Exit: {'✅' if self.plant_mode_exited else '❌'}")
        print(f"   Dynamic Scanning: {'✅' if self.dynamic_scanning else '❌'}")
        print(f"   Fully Active: {'✅' if self.radar_fully_active else '❌'}")

    def run_activation_sequence(self, duration=300):
        """Run complete radar activation sequence"""
        print("🚀 TESLA RADAR ACTIVATOR - COMPLETE IMPLEMENTATION")
        print("=" * 70)
        print("Based on working Panda safety layer implementation")
        print("Features:")
        print("  ✅ Complete Tesla protocol with proper timing")
        print("  ✅ 13 Tesla messages at correct frequencies")
        print("  ✅ Proper VIN transmission (3-part protocol)")
        print("  ✅ CRC/checksum validation")
        print("  ✅ 0x631 initialization detection")
        print("  ✅ Enhanced radar monitoring")
        print("  ✅ OpenPilot-style object validation")
        print()

        print(f"🎯 Configuration:")
        print(f"   VIN: {self.protocol.radar_VIN}")
        print(f"   Position: {self.protocol.radarPosition}")
        print(f"   EPAS Type: {self.protocol.radarEpasType}")
        print(f"   Speed: {self.protocol.actual_speed_kph} km/h")
        print(f"   Duration: {duration}s")
        print()

        self.running = True
        self.start_time = time.time()

        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_radar_behavior)
        monitor_thread.daemon = True
        monitor_thread.start()

        # Start Tesla protocol
        protocol_thread = threading.Thread(target=self.protocol.start)
        protocol_thread.daemon = True
        protocol_thread.start()

        print("🔍 MONITORING FOR RADAR ACTIVATION...")
        print("Looking for:")
        print("  1. 0x631 radar initialization signal")
        print("  2. 0x300 radar status confirmation")
        print("  3. VIN transmission completion (7 cycles)")
        print("  4. Plant mode → Active transition")
        print("  5. Dynamic scan index changes")
        print("  6. Valid object detection")
        print()

        try:
            # Main monitoring loop
            end_time = time.time() + duration

            while time.time() < end_time and self.running:
                # Check for success conditions
                if self.radar_fully_active:
                    print("\n🎉 SUCCESS! RADAR FULLY OPERATIONAL!")
                    self.print_success_summary()
                    break

                time.sleep(1)

            # Final status
            if not self.radar_fully_active:
                print("\n⚠️  ACTIVATION INCOMPLETE")
                self.print_diagnostic_summary()

        except KeyboardInterrupt:
            print("\n❌ Activation interrupted by user")
        finally:
            self.running = False
            self.protocol.stop()

    def print_success_summary(self):
        """Print success summary with key metrics"""
        elapsed = time.time() - self.start_time

        self.init_631_count = max(
            self.init_631_count, getattr(self.protocol, "init_message_count", 0)
        )
        self.status_300_count = max(
            self.status_300_count, getattr(self.protocol, "status_message_count", 0)
        )

        print("\n" + "=" * 70)
        print("🎉 RADAR ACTIVATION SUCCESS!")
        print("=" * 70)
        print(f"⏱️  Total Time: {elapsed:.1f}s")
        print(f"🔄 Init Messages: {self.init_631_count}")
        print(f"📊 Status Messages: {self.status_300_count}")
        print(f"📡 VIN Cycles: {self.protocol.tesla_radar_vin_complete}/7")
        print(f"🎯 Valid Objects: {self.valid_objects}")
        print(f"📈 Scan Indices: {len(set(self.scan_indices))} unique values")
        print(f"⚡ Power Level: {max(self.power_levels) if self.power_levels else 0}")
        print()
        print("✅ All systems operational!")
        print("✅ Radar is actively scanning and tracking objects")
        print("✅ Plant mode successfully exited")
        print("✅ Full Tesla protocol implementation working")
        print()
        print("🎯 MISSION ACCOMPLISHED!")

    def print_diagnostic_summary(self):
        """Print diagnostic summary for troubleshooting"""
        elapsed = time.time() - self.start_time

        self.init_631_count = max(
            self.init_631_count, getattr(self.protocol, "init_message_count", 0)
        )
        self.status_300_count = max(
            self.status_300_count, getattr(self.protocol, "status_message_count", 0)
        )

        print("\n" + "=" * 70)
        print("📊 DIAGNOSTIC SUMMARY")
        print("=" * 70)
        print(f"⏱️  Total Time: {elapsed:.1f}s")
        print(f"🔄 Init Messages (0x631): {self.init_631_count}")
        print(f"📊 Status Messages (0x300): {self.status_300_count}")
        print(f"📡 VIN Completion: {self.protocol.tesla_radar_vin_complete}/7")
        print(f"🎯 Valid Objects: {self.valid_objects}")
        print(f"📈 Unique Scan Indices: {len(set(self.scan_indices))}")
        print(
            f"⚡ Max Power Level: {max(self.power_levels) if self.power_levels else 0}"
        )
        print(f"⚠️  Error Codes: {len(self.error_codes)}")
        if getattr(self.protocol, "error_code_counts", None):
            total_errors = sum(self.protocol.error_code_counts.values())
            print(
                f"   0x3FF status: {len(self.protocol.error_code_counts)} unique / {total_errors} total"
            )
            top_codes = sorted(
                self.protocol.error_code_counts.items(),
                key=lambda item: item[1],
                reverse=True,
            )[:5]
            if top_codes:
                formatted = ", ".join(
                    f"{code}:{count} ({self.protocol.describe_error_code(code)})"
                    for code, count in top_codes
                )
                print(f"   Top error codes: {formatted}")
            if self.debug:
                for code, count in sorted(
                    self.protocol.error_code_counts.items(), key=lambda item: item[0]
                ):
                    desc = self.protocol.describe_error_code(code)
                    payloads = list(self.protocol.error_code_payloads.get(code, []))[:3]
                    payload_str = ", ".join(payloads) if payloads else ""
                    print(
                        f"      - {code}: {desc} (count {count})"
                        + (f" payloads: {payload_str}" if payload_str else "")
                    )
        print()

        # Specific diagnostics
        print("🔍 SPECIFIC ISSUES:")

        if self.init_631_count == 0:
            print("   ❌ No 0x631 initialization detected")
            print("      → Check radar power and CAN connections")

        if self.protocol.tesla_radar_vin_complete < 7:
            print("   ❌ VIN transmission incomplete")
            print("      → Check 0x2B9 message transmission")

        if not self.plant_mode_exited:
            print("   ❌ Plant mode not exited")
            print("      → Check radar position/EPAS configuration")

        if not self.dynamic_scanning:
            print("   ❌ Scan index static")
            print("      → Try different radarPosition/radarEpasType values")

        if self.valid_objects == 0:
            print("   ❌ No valid objects detected")
            print("      → Check object detection logic")

        # Recommendations
        print("\n💡 RECOMMENDATIONS:")
        print("   1. Try different radarPosition values (0, 1, 2)")
        print("   2. Try different radarEpasType values (0, 1)")
        print("   3. Check physical radar mounting and connections")
        print("   4. Verify CAN bus termination")
        print("   5. Try longer activation duration")

    def test_configurations(self):
        """Test different radar configurations systematically"""
        print("🧪 TESTING RADAR CONFIGURATIONS")
        print("=" * 50)

        # Test configurations for 2016 Model S
        configs = [
            (0, 0),  # Model S pre-facelift + Bosch L538
            (0, 1),  # Model S pre-facelift + Bosch L405
            (1, 0),  # Model S post-facelift + Bosch L538
            (1, 1),  # Model S post-facelift + Bosch L405
            (2, 0),  # Model X + Bosch L538
            (2, 1),  # Model X + Bosch L405
        ]

        best_config = None
        best_score = 0

        for i, (pos, epas) in enumerate(configs):
            print(
                f"\n🔧 Testing Config {i+1}/{len(configs)}: Position={pos}, EPAS={epas}"
            )

            # Update configuration
            self.protocol.radarPosition = pos
            self.protocol.radarEpasType = epas

            # Reset counters
            self.init_631_count = 0
            self.valid_objects = 0
            self.scan_indices = []
            self.power_levels = []
            self.plant_mode_exited = False
            self.dynamic_scanning = False

            # Test for 90 seconds
            self.run_activation_sequence(duration=90)

            # Calculate score
            score = 0
            if self.init_631_count > 0:
                score += 20
            if self.plant_mode_exited:
                score += 30
            if self.dynamic_scanning:
                score += 30
            if self.valid_objects > 0:
                score += 20

            print(f"   Score: {score}/100")

            if score > best_score:
                best_score = score
                best_config = (pos, epas)

            if score == 100:
                print("   🎉 PERFECT CONFIGURATION FOUND!")
                break

            time.sleep(2)  # Brief pause between tests

        print(f"\n🏆 BEST CONFIGURATION:")
        if best_config:
            pos, epas = best_config
            print(f"   Position: {pos}, EPAS: {epas}")
            print(f"   Score: {best_score}/100")
        else:
            print("   No successful configuration found")


def main():
    parser = argparse.ArgumentParser(
        description="Tesla Radar Activator - Complete Implementation"
    )
    parser.add_argument("--can-interface", default="can1", help="CAN interface")
    parser.add_argument("--vin", default="5YJSB7E43GF113105", help="Vehicle VIN")
    parser.add_argument("--position", type=int, default=0, help="Radar position (0-2)")
    parser.add_argument("--epas", type=int, default=0, help="EPAS type (0-1)")
    parser.add_argument("--speed", type=int, default=30, help="Simulated speed (km/h)")
    parser.add_argument("--duration", type=int, default=300, help="Duration (seconds)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument(
        "--test-configs", action="store_true", help="Test all configurations"
    )

    args = parser.parse_args()

    # Setup CAN
    can_bus = setup_can(interface=args.can_interface)

    try:
        activator = TeslaRadarActivator(can_bus, vin=args.vin, debug=args.debug)

        # Configure radar
        activator.protocol.radarPosition = args.position
        activator.protocol.radarEpasType = args.epas
        activator.protocol.actual_speed_kph = args.speed
        activator.protocol.base_speed_kph = args.speed

        if args.test_configs:
            activator.test_configurations()
        else:
            activator.run_activation_sequence(duration=args.duration)

    except KeyboardInterrupt:
        print("\n❌ Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()
    finally:
        can_bus.shutdown()
        print("\nCAN interface closed")


if __name__ == "__main__":
    main()
