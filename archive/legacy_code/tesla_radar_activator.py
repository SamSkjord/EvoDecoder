#!/usr/bin/env python3
"""
Tesla Radar Activator - Complete Implementation
Based on working Panda safety layer implementation
Combines proper Tesla protocol with comprehensive monitoring
"""

import os
import json
import time
import can
import argparse
import threading
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Any, Dict, Optional

from tesla_radar_protocol import TeslaRadarProtocol, setup_can


class SCPIPowerController:
    """Simple SCPI power controller for the bench supply."""

    def __init__(
        self,
        port: str,
        baud: int = 115200,
        off_time: float = 1.5,
        wait_before_activation: float = 3.0,
    ) -> None:
        self.port = port
        self.baud = baud
        self.off_time = max(0.1, off_time)
        # Ensure we always meet the ≥3 s requirement
        self.wait_before_activation = max(3.0, wait_before_activation)

    def cycle(self) -> None:
        try:
            import serial
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "pyserial is required for SCPI power control; install with `pip install pyserial`."
            ) from exc

        print(
            f"🔋 Cycling radar power on {self.port} (off {self.off_time:.1f}s, wait {self.wait_before_activation:.1f}s)"
        )

        with serial.Serial(self.port, self.baud, timeout=1) as ser:
            ser.write(b"OUTP 0\r\n")
            ser.flush()
            time.sleep(self.off_time)
            ser.write(b"OUTP 1\r\n")
            ser.flush()

        time.sleep(self.wait_before_activation)



class TeslaRadarActivator:
    """Complete Tesla Radar Activation System"""

    def __init__(
        self,
        can_bus,
        vin="5YJSB7E43GF113105",
        debug=False,
        *,
        power_controller: Optional[SCPIPowerController] = None,
        run_log_path: Optional[str] = None,
        **protocol_kwargs,
    ):
        self.can_bus = can_bus
        self.debug = debug
        self.running = False
        self.power_controller = power_controller

        # Initialize Tesla protocol
        self.protocol = TeslaRadarProtocol(
            can_bus, vin=vin, debug=debug, **protocol_kwargs
        )

        # Monitoring state
        self.scan_indices = []
        self.power_levels = []
        self.error_codes = set()
        self.valid_objects = 0
        self.paired_messages = 0
        self.init_631_count = 0
        self.status_300_count = 0
        self.error_code_payloads = defaultdict(set)
        self.status_transitions = []
        self._last_status_state = None
        self.vin_progress = []
        self._last_vin_count = 0
        self._run_index = 0
        self._current_run_id: Optional[str] = None
        self._current_metadata: Optional[Dict[str, Any]] = None

        # Success tracking
        self.plant_mode_exited = False
        self.radar_fully_active = False
        self.dynamic_scanning = False

        # Statistics
        self.start_time = time.time()
        self.last_status_update = time.time()
        self.message_stats = {}

        default_log_path = (
            Path(__file__).resolve().parent.parent / "radar_run_history.jsonl"
        )
        self.run_log_path = Path(run_log_path).expanduser() if run_log_path else default_log_path
        self.run_log_path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _encode_country(value: Optional[str]) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, int):
            return value
        value = value.strip()
        if value.startswith("0x"):
            return int(value, 16)
        if value.isdigit():
            return int(value)
        if len(value) == 2:
            return (ord(value[0]) << 8) | ord(value[1])
        raise ValueError(
            "country must be provided as integer, hex string, or two-character ASCII code"
        )

    def _generate_run_id(self) -> str:
        self._run_index += 1
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        return f"run-{timestamp}-{self._run_index:03d}"

    def _prepare_for_run(self, run_id: str, metadata: Optional[Dict[str, Any]]) -> None:
        self._current_run_id = run_id
        self._current_metadata = metadata.copy() if metadata else None
        self.status_transitions = []
        self._last_status_state = None
        self.vin_progress = []
        self.scan_indices = []
        self.power_levels = []
        self.error_codes = set()
        self.error_code_payloads = defaultdict(set)
        self.init_631_count = 0
        self.status_300_count = 0
        self.valid_objects = 0
        self.paired_messages = 0
        self.plant_mode_exited = False
        self.radar_fully_active = False
        self.dynamic_scanning = False
        self.message_stats = {}

        # Reset protocol-side counters for a clean run snapshot
        self.protocol.error_code_counts.clear()
        self.protocol.error_code_payloads.clear()
        self.protocol.init_message_count = 0
        self.protocol.status_message_count = 0
        self.protocol.tesla_radar_status = 0
        self.protocol.tesla_radar_vin_complete = 0
        self._last_vin_count = 0

    def _enforce_power_cycle(self) -> None:
        if self.power_controller is None:
            return
        self.power_controller.cycle()

    def _record_status_transition(
        self, state: int, scan_index: int, power_level: int, raw_data: bytes
    ) -> None:
        if state == self._last_status_state and self.status_transitions:
            return
        elapsed = max(0.0, time.time() - self.start_time)
        self.status_transitions.append(
            {
                "t": round(elapsed, 3),
                "state": int(state),
                "scan": int(scan_index),
                "power": int(power_level),
                "raw": raw_data.hex(),
            }
        )
        self._last_status_state = state

    def _record_vin_progress(self) -> None:
        current = int(getattr(self.protocol, "tesla_radar_vin_complete", 0))
        if current == self._last_vin_count:
            return
        elapsed = max(0.0, time.time() - self.start_time)
        self.vin_progress.append({"t": round(elapsed, 3), "cycles": current})
        self._last_vin_count = current

    def _gateway_snapshot(self) -> Dict[str, Any]:
        proto = self.protocol
        return {
            "GTW_fourWheelDrive": 1 if proto.force_awd else 0,
            "GTW_airSuspensionInstalled": proto.gateway_air_suspension,
            "GTW_performanceConfig": proto.gateway_performance_config,
            "GTW_chassisType": proto.gateway_chassis_type,
            "GTW_epasType": proto.gateway_epas_type,
            "GTW_autopilot": proto.gateway_autopilot_level,
            "GTW_country": proto.gateway_country,
            "GTW_rhd": proto.gateway_rhd,
            "GTW_forwardRadarHw": proto.gateway_forward_radar_hw,
            "GTW_parkAssistInstalled": proto.gateway_park_assist,
            "GTW_wheelType": proto.gateway_wheel_type,
            "GTW_brakeHwType": proto.gateway_brake_hw_type,
            "GTW_foldingMirrorsInstalled": proto.gateway_folding_mirrors,
            "GTW_parkSensorGeometryType": proto.gateway_park_sensor_geometry,
            "GTW_euVehicle": proto.gateway_eu_vehicle,
            "radarPosition": proto.radarPosition,
            "radarEpasType": proto.radarEpasType,
        }

    def _build_error_payload_maps(self) -> Dict[str, Any]:
        payloads_by_code = {
            f"{int(code):02X}": sorted(list(payloads))
            for code, payloads in self.error_code_payloads.items()
        }
        grouped = defaultdict(set)
        for code, payloads in self.error_code_payloads.items():
            base_code = int(code) & 0x7F
            grouped[f"{base_code:02X}"].update(payloads)
        payloads_by_base = {
            base: sorted(list(payloads)) for base, payloads in grouped.items()
        }
        return {
            "by_code": payloads_by_code,
            "by_base": payloads_by_base,
        }

    def _persist_run_record(self, record: Dict[str, Any]) -> None:
        try:
            with self.run_log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception as exc:
            print(f"⚠️  Failed to write run log {self.run_log_path}: {exc}")

    def _collect_run_record(self, duration: int) -> Dict[str, Any]:
        payload_maps = self._build_error_payload_maps()
        error_codes_sorted = sorted(int(code) for code in self.error_codes if code)
        base_codes = sorted({code & 0x7F for code in error_codes_sorted if code & 0x7F})
        record: Dict[str, Any] = {
            "run_id": self._current_run_id,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "vin": self.protocol.radar_VIN,
            "duration_s": duration,
            "gateway_params": self._gateway_snapshot(),
            "status_transitions": self.status_transitions,
            "vin_progress": self.vin_progress,
            "vin_complete": int(self.protocol.tesla_radar_vin_complete),
            "error_codes": error_codes_sorted,
            "error_codes_hex": [f"{code:02X}" for code in error_codes_sorted],
            "error_base_codes": base_codes,
            "error_base_codes_hex": [f"{code:02X}" for code in base_codes],
            "error_base_codes_names": {
                f"{code:02X}": self.protocol.describe_error_code(code)
                for code in base_codes
            },
            "error_payloads_by_code": payload_maps["by_code"],
            "error_payloads_by_base": payload_maps["by_base"],
            "error_code_counts": {
                f"{int(code):02X}": int(count)
                for code, count in sorted(self.protocol.error_code_counts.items())
            },
            "init_messages": int(self.init_631_count),
            "status_messages": int(self.status_300_count),
            "success_flags": {
                "plant_mode_exited": bool(self.plant_mode_exited),
                "dynamic_scanning": bool(self.dynamic_scanning),
                "radar_fully_active": bool(self.radar_fully_active),
            },
        }

        if self._current_metadata is not None:
            record["metadata"] = self._current_metadata

        if self.scan_indices:
            record["scan_index_samples"] = self.scan_indices[-20:]
        if self.power_levels:
            record["power_level_samples"] = self.power_levels[-20:]

        return record

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
                        self._record_status_transition(
                            radar_state, scan_index, power_level, msg.data
                        )

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
                            self.error_code_payloads[error_code].add(msg.data.hex())
                            if self.debug:
                                print(f"⚠️  ERROR CODE (0x3FF): {error_code}")

                # Monitor object tracking messages (0x310-0x36F)
                elif 0x310 <= msg_id <= 0x36F:
                    self.analyze_object_message(msg_id, msg.data)

            # Update status periodically
            if time.time() - self.last_status_update >= 5.0:
                self.update_status()
                self.last_status_update = time.time()

            self._record_vin_progress()

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

    def run_activation_sequence(
        self,
        duration: int = 300,
        *,
        run_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Run complete radar activation sequence and return the logged record."""

        resolved_run_id = run_id or self._generate_run_id()
        self._prepare_for_run(resolved_run_id, metadata)

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

        print("🎯 Configuration:")
        print(f"   Run ID: {resolved_run_id}")
        print(f"   VIN: {self.protocol.radar_VIN}")
        print(f"   Position: {self.protocol.radarPosition}")
        print(f"   EPAS Type: {self.protocol.radarEpasType}")
        print(f"   Speed: {self.protocol.actual_speed_kph} km/h")
        print(f"   Duration: {duration}s")
        print()

        monitor_thread: Optional[threading.Thread] = None
        protocol_thread: Optional[threading.Thread] = None

        self._enforce_power_cycle()

        self.running = True
        self.start_time = time.time()
        self.last_status_update = self.start_time

        monitor_thread = threading.Thread(target=self.monitor_radar_behavior, daemon=True)
        protocol_thread = threading.Thread(target=self.protocol.start, daemon=True)

        monitor_thread.start()
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

        run_record: Dict[str, Any] = {}

        try:
            end_time = time.time() + duration

            while time.time() < end_time and self.running:
                if self.radar_fully_active:
                    print("\n🎉 SUCCESS! RADAR FULLY OPERATIONAL!")
                    self.print_success_summary()
                    break

                time.sleep(1)

            if not self.radar_fully_active:
                print("\n⚠️  ACTIVATION INCOMPLETE")
                self.print_diagnostic_summary()

        except KeyboardInterrupt:
            print("\n❌ Activation interrupted by user")
        finally:
            self.running = False
            try:
                self.protocol.stop()
            finally:
                if monitor_thread and monitor_thread.is_alive():
                    monitor_thread.join(timeout=2.0)
                if protocol_thread and protocol_thread.is_alive():
                    protocol_thread.join(timeout=2.0)
            self._record_vin_progress()
            run_record = self._collect_run_record(duration)
            self._persist_run_record(run_record)
            print(f"📝 Run {resolved_run_id} logged to {self.run_log_path}")

        return run_record

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
    parser.add_argument("--performance-config", type=int, help="GTW_performanceConfig value")
    parser.add_argument("--air-suspension", type=int, help="GTW_airSuspensionInstalled value")
    parser.add_argument("--chassis-type", type=int, help="GTW_chassisType value")
    parser.add_argument(
        "--four-wheel-drive",
        type=int,
        choices=[0, 1],
        help="Override GTW_fourWheelDrive (0/1)",
    )
    parser.add_argument(
        "--autopilot-level", type=int, help="GTW_autopilot enumerated level"
    )
    parser.add_argument(
        "--country",
        help="GTW_country value (int, hex, or two-character ASCII)",
    )
    parser.add_argument(
        "--forward-radar-hw", type=int, help="GTW_forwardRadarHw value"
    )
    parser.add_argument(
        "--park-assist", type=int, help="GTW_parkAssistInstalled value"
    )
    parser.add_argument("--wheel-type", type=int, help="GTW_wheelType value")
    parser.add_argument(
        "--brake-hw-type", type=int, help="GTW_brakeHwType value"
    )
    parser.add_argument(
        "--folding-mirrors", type=int, help="GTW_foldingMirrorsInstalled value"
    )
    parser.add_argument(
        "--park-geometry", type=int, help="GTW_parkSensorGeometryType value"
    )
    parser.add_argument(
        "--eu-vehicle",
        type=int,
        choices=[0, 1],
        help="GTW_euVehicle flag (0 or 1)",
    )
    parser.add_argument("--das-hw", type=int, help="GTW_dasHw value")
    parser.add_argument(
        "--raw-398",
        help="Override GTW 0x398 payload with 8-byte hex (e.g. 0186555311310A08)",
    )

    parser.add_argument("--run-id", help="Explicit run identifier for logging")
    parser.add_argument(
        "--log-path",
        help="Override run history log location (default: radar_run_history.jsonl)",
    )
    parser.add_argument(
        "--scpi-port",
        default="/dev/cu.usbserial-2230",
        help="SCPI serial port (default: /dev/cu.usbserial-2230) for enforced power cycles",
    )
    parser.add_argument(
        "--scpi-off-time",
        type=float,
        default=1.5,
        help="Seconds to hold power off before turning back on",
    )
    parser.add_argument(
        "--scpi-wait",
        type=float,
        default=3.0,
        help="Seconds to wait after power on before activation (min 3.0s)",
    )
    parser.add_argument(
        "--no-scpi",
        action="store_true",
        help="Disable SCPI power cycling (use with caution only when hardware already power-cycled)",
    )

    args = parser.parse_args()

    # Setup CAN
    can_bus = setup_can(interface=args.can_interface)

    power_controller = None
    if not args.no_scpi and args.scpi_port:
        power_controller = SCPIPowerController(
            args.scpi_port,
            off_time=args.scpi_off_time,
            wait_before_activation=args.scpi_wait,
        )

    proto_kwargs = {}
    if args.performance_config is not None:
        proto_kwargs["performance_config"] = args.performance_config
    if args.air_suspension is not None:
        proto_kwargs["air_suspension"] = args.air_suspension
    if args.chassis_type is not None:
        proto_kwargs["chassis_type"] = args.chassis_type
    if args.four_wheel_drive is not None:
        proto_kwargs["four_wheel_drive"] = args.four_wheel_drive
    if args.autopilot_level is not None:
        proto_kwargs["autopilot_level"] = args.autopilot_level

    try:
        activator = TeslaRadarActivator(
            can_bus,
            vin=args.vin,
            debug=args.debug,
            power_controller=power_controller,
            run_log_path=args.log_path,
            **proto_kwargs,
        )

        # Configure radar
        activator.protocol.radarPosition = args.position
        activator.protocol.radarEpasType = args.epas
        activator.protocol.gateway_epas_type = args.epas
        if args.four_wheel_drive is not None:
            activator.protocol.force_awd = bool(args.four_wheel_drive)
        activator.protocol.actual_speed_kph = args.speed
        activator.protocol.base_speed_kph = args.speed
        if args.country is not None:
            activator.protocol.gateway_country = TeslaRadarActivator._encode_country(
                args.country
            )
        if args.forward_radar_hw is not None:
            activator.protocol.gateway_forward_radar_hw = args.forward_radar_hw
        if args.park_assist is not None:
            activator.protocol.gateway_park_assist = args.park_assist
        if args.wheel_type is not None:
            activator.protocol.gateway_wheel_type = args.wheel_type
        if args.brake_hw_type is not None:
            activator.protocol.gateway_brake_hw_type = args.brake_hw_type
        if args.folding_mirrors is not None:
            activator.protocol.gateway_folding_mirrors = args.folding_mirrors
        if args.park_geometry is not None:
            activator.protocol.gateway_park_sensor_geometry = args.park_geometry
        if args.eu_vehicle is not None:
            activator.protocol.gateway_eu_vehicle = args.eu_vehicle
        if args.das_hw is not None:
            activator.protocol.gateway_das_hw = args.das_hw
        if args.raw_398 is not None:
            payload = bytes.fromhex(args.raw_398.strip())
            if len(payload) != 8:
                raise ValueError("--raw-398 must decode to exactly 8 bytes")
            activator.protocol.gateway_raw_398_payload = payload

        if args.test_configs:
            activator.test_configurations()
        else:
            run_record = activator.run_activation_sequence(
                duration=args.duration,
                run_id=args.run_id,
                metadata={"source": "cli"},
            )
            if run_record:
                base_codes = run_record.get("error_base_codes_hex", [])
                print(f"Base 0x3FF codes observed: {base_codes or ['none']}")
                print(
                    f"VIN completion: {run_record.get('vin_complete', 'n/a')}/7, "
                    f"0x631 count: {run_record.get('init_messages', 'n/a')}"
                )

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
