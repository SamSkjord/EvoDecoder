import json
import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parent.parent
CODE_DIR = ROOT / "code"
if str(CODE_DIR) not in sys.path:
    sys.path.append(str(CODE_DIR))

from tesla_radar_activator import SCPIPowerController, TeslaRadarActivator
from tesla_radar_protocol import setup_can, get_plant_failure_map

DEFAULT_VIN = "5YJSB7E43GF113105"
DEFAULT_INTERFACE = "can1"
DEFAULT_DURATION = 4.0
DEFAULT_HISTORY_PATH = ROOT / "gateway_probe_history.jsonl"
DEFAULT_RUN_LOG_PATH = ROOT / "radar_run_history.jsonl"
DEFAULT_SCPI_PORT = "/dev/cu.usbserial-2230"
DEFAULT_SCPI_OFF_TIME = 1.5
DEFAULT_SCPI_WAIT = 3.0
DEFAULT_AGGREGATE_PATH = ROOT / "gateway_probe_results.json"

_FAILURE_MAP: Optional[Dict[int, str]] = None


def _describe_base_code(code_hex: str) -> str:
    global _FAILURE_MAP
    if _FAILURE_MAP is None:
        _FAILURE_MAP = get_plant_failure_map()
    try:
        code_int = int(code_hex, 16)
    except ValueError:
        return "UNKNOWN"
    return _FAILURE_MAP.get(code_int, "UNKNOWN")


def append_history_entry(path: Path, entry: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def _first_value(params: Dict[str, Any], keys: Iterable[str]) -> Optional[Any]:
    for key in keys:
        if key in params:
            return params[key]
    return None


def _parse_country(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        val = value.strip()
        if val.startswith("0x"):
            return int(val, 16)
        if val.isdigit():
            return int(val)
        if len(val) == 2:
            return (ord(val[0]) << 8) | ord(val[1])
    raise ValueError(
        "GTW_country must be provided as integer, hex string, or two-character ASCII"
    )


def extract_protocol_kwargs(params: Dict[str, Any]) -> Dict[str, Any]:
    mappings = [
        (["GTW_performanceConfig", "performance_config"], "performance_config"),
        (["GTW_airSuspensionInstalled", "air_suspension"], "air_suspension"),
        (["GTW_chassisType", "chassis_type"], "chassis_type"),
        (["GTW_fourWheelDrive", "four_wheel_drive"], "four_wheel_drive"),
        (["GTW_autopilot", "autopilot_level"], "autopilot_level"),
    ]
    result: Dict[str, Any] = {}
    for keys, target in mappings:
        value = _first_value(params, keys)
        if value is not None:
            result[target] = value
    return result


def apply_gateway_params(proto, params: Dict[str, Any]) -> None:
    def set_attr(attr: str, keys: Iterable[str]) -> None:
        value = _first_value(params, keys)
        if value is None:
            return
        setattr(proto, attr, int(value))

    set_attr("gateway_performance_config", ["GTW_performanceConfig", "performance_config"])
    set_attr("gateway_air_suspension", ["GTW_airSuspensionInstalled", "air_suspension"])
    set_attr("gateway_chassis_type", ["GTW_chassisType", "chassis_type"])
    set_attr("gateway_autopilot_level", ["GTW_autopilot", "autopilot_level"])
    set_attr("gateway_rhd", ["GTW_rhd", "rhd"])
    set_attr("gateway_epas_type", ["GTW_epasType", "epas_type"])
    set_attr("gateway_forward_radar_hw", ["GTW_forwardRadarHw"])
    set_attr("gateway_park_assist", ["GTW_parkAssistInstalled"])
    set_attr("gateway_wheel_type", ["GTW_wheelType", "wheel_type"])
    set_attr("gateway_brake_hw_type", ["GTW_brakeHwType", "brake_hw_type"])
    set_attr("gateway_folding_mirrors", ["GTW_foldingMirrorsInstalled", "folding_mirrors"])
    set_attr("gateway_park_sensor_geometry", ["GTW_parkSensorGeometryType", "park_sensor_geometry_type"])
    set_attr("gateway_eu_vehicle", ["GTW_euVehicle", "eu_vehicle"])
    country_value = _first_value(params, ["GTW_country", "country"])
    if country_value is not None:
        proto.gateway_country = _parse_country(country_value)

    awd_value = _first_value(params, ["GTW_fourWheelDrive", "four_wheel_drive"])
    if awd_value is not None:
        proto.force_awd = bool(awd_value)

    radar_position = _first_value(params, ["radarPosition"])
    if radar_position is not None:
        proto.radarPosition = int(radar_position)

    radar_epas = _first_value(params, ["radarEpasType"])
    if radar_epas is not None:
        proto.radarEpasType = int(radar_epas)
        proto.gateway_epas_type = int(radar_epas)

    speed = _first_value(params, ["speed_kph", "speed", "vehicle_speed_kph"])
    if speed is None:
        speed = 30
    proto.actual_speed_kph = float(speed)
    proto.base_speed_kph = float(speed)


def run_gateway_probe(
    params: Dict[str, Any],
    *,
    vin: str,
    interface: str,
    duration_s: float,
    power_controller: Optional[SCPIPowerController],
    run_log_path: Path,
    run_id: Optional[str] = None,
    label: Optional[str] = None,
    source: str = "gateway_probe",
    metadata_extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    duration = max(1, int(round(duration_s)))
    bus = setup_can(interface=interface)
    activator: Optional[TeslaRadarActivator] = None
    try:
        proto_kwargs = extract_protocol_kwargs(params)
        activator = TeslaRadarActivator(
            bus,
            vin=vin,
            debug=False,
            power_controller=power_controller,
            run_log_path=str(run_log_path),
            **proto_kwargs,
        )
        proto = activator.protocol
        apply_gateway_params(proto, params)

        metadata: Dict[str, Any] = {"source": source, "params": params}
        if label:
            metadata["label"] = label
        if metadata_extra:
            metadata.update(metadata_extra)

        record = activator.run_activation_sequence(
            duration=duration,
            run_id=run_id,
            metadata=metadata,
        )
        return record
    finally:
        if activator is not None:
            try:
                activator.protocol.stop()
            except Exception:
                pass
        bus.shutdown()


def build_history_entry(
    record: Dict[str, Any],
    params: Dict[str, Any],
    *,
    label: Optional[str] = None,
    duration_s: Optional[float] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "timestamp": record.get("timestamp"),
        "run_id": record.get("run_id"),
        "vin": record.get("vin"),
        "label": label,
        "params": params,
        "duration_s": duration_s if duration_s is not None else record.get("duration_s"),
        "vin_complete": record.get("vin_complete"),
        "has_0x631": bool(record.get("init_messages", 0)),
        "init_messages": record.get("init_messages"),
        "status_messages": record.get("status_messages"),
        "error_codes_hex": record.get("error_codes_hex"),
        "error_base_codes_hex": record.get("error_base_codes_hex"),
        "error_base_codes_names": record.get("error_base_codes_names"),
        "error_payloads_by_base": record.get("error_payloads_by_base"),
        "error_payloads_by_code": record.get("error_payloads_by_code"),
        "success_flags": record.get("success_flags"),
    }
    if notes:
        entry["notes"] = notes
    if isinstance(record.get("metadata"), dict):
        entry["metadata"] = record["metadata"]
    return entry


def _read_history_entries(history_path: Path) -> List[Dict[str, Any]]:
    if not history_path.exists():
        return []
    entries: List[Dict[str, Any]] = []
    with history_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            text = line.strip()
            if not text:
                continue
            try:
                entry = json.loads(text)
            except json.JSONDecodeError:
                continue
            entries.append(entry)
    unique: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    for index, entry in enumerate(entries):
        key = entry.get("run_id") or f"idx-{index}"
        unique[key] = entry
    return list(unique.values())


def update_aggregate_from_history(
    history_path: Path,
    aggregate_path: Optional[Path] = None,
) -> Dict[str, Any]:
    aggregate_path = aggregate_path or DEFAULT_AGGREGATE_PATH
    entries = _read_history_entries(history_path)
    if not entries:
        aggregate = {
            "updated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "history_path": str(history_path),
            "runs": [],
        }
        aggregate_path.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
        return aggregate

    def is_baseline(entry: Dict[str, Any]) -> bool:
        metadata = entry.get("metadata") or {}
        return (
            metadata.get("phase") == "baseline"
            or entry.get("label") == "baseline"
            or entry.get("run_id") == "baseline"
        )

    baseline_entry = next((entry for entry in entries if is_baseline(entry)), entries[0])
    baseline_codes = set(baseline_entry.get("error_base_codes_hex") or [])
    baseline_hex = sorted(baseline_codes)
    baseline_names = {
        code: _describe_base_code(code) for code in baseline_hex
    }

    aggregated_runs: List[Dict[str, Any]] = []
    for entry in entries:
        codes = set(entry.get("error_base_codes_hex") or [])
        codes_hex = sorted(codes)
        names = {code: _describe_base_code(code) for code in codes_hex}
        new_codes = sorted(codes - baseline_codes)
        cleared_codes = sorted(baseline_codes - codes)
        aggregated_runs.append(
            {
                "run_id": entry.get("run_id"),
                "label": entry.get("label"),
                "metadata": entry.get("metadata"),
                "params": entry.get("params"),
                "vin_complete": entry.get("vin_complete"),
                "has_0x631": entry.get("has_0x631"),
                "error_base_codes_hex": codes_hex,
                "error_base_codes_names": names,
                "new_vs_baseline": new_codes,
                "cleared_vs_baseline": cleared_codes,
                "error_payloads_by_base": entry.get("error_payloads_by_base"),
                "error_payloads_by_code": entry.get("error_payloads_by_code"),
            }
        )

    aggregate = {
        "updated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "history_path": str(history_path),
        "baseline": {
            "run_id": baseline_entry.get("run_id"),
            "label": baseline_entry.get("label"),
            "error_base_codes_hex": baseline_hex,
            "error_base_codes_names": baseline_names,
            "vin_complete": baseline_entry.get("vin_complete"),
            "has_0x631": baseline_entry.get("has_0x631"),
            "error_payloads_by_base": baseline_entry.get("error_payloads_by_base"),
        },
        "runs": aggregated_runs,
    }

    aggregate_path.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
    return aggregate


__all__ = [
    "DEFAULT_DURATION",
    "DEFAULT_HISTORY_PATH",
    "DEFAULT_INTERFACE",
    "DEFAULT_AGGREGATE_PATH",
    "DEFAULT_RUN_LOG_PATH",
    "DEFAULT_SCPI_OFF_TIME",
    "DEFAULT_SCPI_PORT",
    "DEFAULT_SCPI_WAIT",
    "DEFAULT_VIN",
    "SCPIPowerController",
    "append_history_entry",
    "build_history_entry",
    "run_gateway_probe",
    "update_aggregate_from_history",
]
