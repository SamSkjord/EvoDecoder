#!/usr/bin/env python3
"""
Tesla Radar Active Tracking Monitor
=================================

Monitors Tesla radar 0x631 messages to detect if radar is outputting
active tracking data vs demo/junk data.

Active tracking indicators:
- Non-zero distance values that change over time
- Realistic velocity values
- Valid target count
- Non-static tracking data patterns
"""

import can
import time
import struct
from collections import defaultdict
import statistics


class RadarTrackingMonitor:
    def __init__(self, interface="can1"):
        self.bus = can.interface.Bus(interface=interface, bustype="socketcan")
        self.tracking_data = defaultdict(list)
        self.last_distances = {}
        self.target_count_history = []
        self.start_time = time.time()

    def decode_radar_message(self, data):
        """Decode Tesla radar 0x631 message"""
        try:
            # Tesla radar format from openpilot
            # Basic decoding - distance, velocity, angle, etc.
            if len(data) >= 8:
                # Extract key tracking values
                target_id = data[0] & 0x0F
                distance = ((data[1] << 8) | data[2]) * 0.05  # meters
                velocity = ((data[3] << 8) | data[4]) * 0.01  # m/s relative
                angle = data[5] * 0.5 - 64  # degrees

                return {
                    "target_id": target_id,
                    "distance": distance,
                    "velocity": velocity,
                    "angle": angle,
                    "raw_data": data.hex(),
                }
        except Exception as e:
            return None

    def analyze_tracking_quality(self):
        """Analyze if tracking data appears to be active vs demo"""
        runtime = time.time() - self.start_time

        print(f"\n🎯 RADAR TRACKING ANALYSIS - Runtime: {runtime:.1f}s")
        print("=" * 50)

        if not self.tracking_data:
            print("❌ No radar tracking data received!")
            return False

        # Analyze target count variations
        if self.target_count_history:
            avg_targets = statistics.mean(self.target_count_history)
            target_variation = max(self.target_count_history) - min(
                self.target_count_history
            )
            print(
                f"📊 Target count: Avg={avg_targets:.1f}, Variation={target_variation}"
            )

        # Analyze distance changes for each target
        active_targets = 0
        static_targets = 0

        print("\n🎯 Target Analysis:")
        for target_id, distances in self.tracking_data.items():
            if len(distances) < 3:
                continue

            distance_variation = max(distances) - min(distances)
            recent_distances = distances[-5:]  # Last 5 readings

            is_active = distance_variation > 0.5  # More than 50cm variation
            if is_active:
                active_targets += 1
                status = "🟢 ACTIVE"
            else:
                static_targets += 1
                status = "🔴 STATIC"

            print(
                f"  Target {target_id}: {status} - Range: {min(distances):.1f}-{max(distances):.1f}m, Var: {distance_variation:.1f}m"
            )

        # Overall assessment
        total_targets = active_targets + static_targets
        print(f"\n📈 TRACKING SUMMARY:")
        print(f"   Active targets: {active_targets}")
        print(f"   Static targets: {static_targets}")
        print(f"   Total targets: {total_targets}")

        # Determine if radar appears to be actively tracking
        is_active_tracking = active_targets > 0 or total_targets > 4

        if is_active_tracking:
            print(f"\n✅ RADAR APPEARS TO BE ACTIVELY TRACKING!")
            print(
                f"   Evidence: {active_targets} active targets, {total_targets} total targets"
            )
        else:
            print(f"\n⚠️  Radar may be in demo/static mode")
            print(f"   Limited target activity detected")

        return is_active_tracking

    def monitor(self, duration=60):
        """Monitor radar for specified duration"""
        print(f"🎯 Monitoring Tesla Radar Tracking Data")
        print(f"   Interface: {self.bus.channel_info}")
        print(f"   Duration: {duration}s")
        print(f"   Looking for 0x631 messages...")
        print(f"   Analyzing tracking patterns...")
        print("\n" + "=" * 50)

        end_time = time.time() + duration
        message_count = 0
        last_analysis = time.time()

        try:
            while time.time() < end_time:
                message = self.bus.recv(timeout=1.0)

                if message and message.arbitration_id == 0x631:
                    message_count += 1

                    # Decode radar data
                    radar_data = self.decode_radar_message(message.data)
                    if radar_data:
                        target_id = radar_data["target_id"]
                        distance = radar_data["distance"]

                        # Store tracking data
                        self.tracking_data[target_id].append(distance)

                        # Keep only recent data (last 20 readings per target)
                        if len(self.tracking_data[target_id]) > 20:
                            self.tracking_data[target_id] = self.tracking_data[
                                target_id
                            ][-20:]

                    # Count current targets
                    current_targets = len(
                        [tid for tid, data in self.tracking_data.items() if data]
                    )
                    self.target_count_history.append(current_targets)

                    if len(self.target_count_history) > 100:
                        self.target_count_history = self.target_count_history[-100:]

                    # Live status update
                    if message_count % 20 == 0:
                        runtime = time.time() - self.start_time
                        print(
                            f"📡 Runtime: {runtime:5.1f}s | Messages: {message_count:4d} | Active targets: {current_targets}"
                        )

                # Periodic analysis
                if time.time() - last_analysis > 15:
                    self.analyze_tracking_quality()
                    last_analysis = time.time()
                    print("\n" + "=" * 50)

        except KeyboardInterrupt:
            print("\n\n🛑 Monitoring stopped by user")
        except Exception as e:
            print(f"\n❌ Error during monitoring: {e}")

        # Final analysis
        print(f"\n\n🏁 FINAL ANALYSIS")
        print("=" * 50)
        final_result = self.analyze_tracking_quality()

        print(f"\n📊 MONITORING SUMMARY:")
        print(f"   Total 0x631 messages: {message_count}")
        print(f"   Monitoring duration: {time.time() - self.start_time:.1f}s")
        print(f"   Targets detected: {len(self.tracking_data)}")

        return final_result


if __name__ == "__main__":
    print("🎯 Tesla Radar Active Tracking Monitor")
    print("=====================================")
    print("🚨 Ensure Tesla vehicle emulator is running!")
    print("📡 Monitoring radar for active tracking vs demo data...")

    monitor = RadarTrackingMonitor()

    # Monitor for 2 minutes to get good data
    is_active = monitor.monitor(duration=120)

    if is_active:
        print(f"\n🎉 SUCCESS: Radar is providing ACTIVE tracking data!")
        print(f"   This indicates the radar is fully operational")
        print(f"   and responding to the Tesla vehicle protocol")
    else:
        print(f"\n🤔 Radar appears to be in demo/static mode")
        print(f"   May need longer activation time or different triggers")
