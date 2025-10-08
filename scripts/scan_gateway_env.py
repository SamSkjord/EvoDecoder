import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from gateway_probe_utils import (
    DEFAULT_AGGREGATE_PATH,
    DEFAULT_DURATION,
    DEFAULT_HISTORY_PATH,
    DEFAULT_INTERFACE,
    DEFAULT_RUN_LOG_PATH,
    DEFAULT_SCPI_OFF_TIME,
    DEFAULT_SCPI_PORT,
    DEFAULT_SCPI_WAIT,
    DEFAULT_VIN,
    SCPIPowerController,
    append_history_entry,
    build_history_entry,
    run_gateway_probe,
    update_aggregate_from_history,
)

BASELINE_PARAMS = {
    "GTW_fourWheelDrive": 1,
    "GTW_airSuspensionInstalled": 3,
    "GTW_performanceConfig": 2,
    "GTW_chassisType": 1,
    "GTW_epasType": 1,
    "GTW_autopilot": 1,
    "GTW_country": "UK",
    "GTW_rhd": 1,
    "GTW_forwardRadarHw": 1,
    "GTW_parkAssistInstalled": 2,
    "GTW_wheelType": 10,
    "GTW_brakeHwType": 2,
    "GTW_foldingMirrorsInstalled": 0,
    "GTW_parkSensorGeometryType": 1,
    "GTW_euVehicle": 1,
    "radarPosition": 0,
    "radarEpasType": 0,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run explicit gateway environment probes from JSON definitions.",
    )
    parser.add_argument(
        "--param-file",
        type=Path,
        help="JSON file defining runs (list or object with 'runs').",
    )
    parser.add_argument("--history", type=Path, help="History JSONL file (appended).")
    parser.add_argument("--run-log", type=Path, help="Activator run log path.")
    parser.add_argument("--vin", help="VIN override for all runs.")
    parser.add_argument("--duration", type=float, help="Default activation duration in seconds.")
    parser.add_argument("--can-interface", help="CAN interface to use (default can1).")
    parser.add_argument("--scpi-port", help="SCPI serial port for power cycling.")
    parser.add_argument("--scpi-off-time", type=float, help="SCPI power-off duration.")
    parser.add_argument("--scpi-wait", type=float, help="SCPI wait-after-on duration.")
    parser.add_argument(
        "--no-scpi",
        action="store_true",
        help="Disable SCPI power cycling (use only if external control handles it).",
    )
    parser.add_argument(
        "--label-prefix",
        help="Prefix for auto-generated labels when JSON entries omit one.",
    )
    parser.add_argument(
        "--aggregate",
        type=Path,
        help="Aggregate JSON output (default gateway_probe_results.json).",
    )
    return parser.parse_args()


def load_runs_from_json(path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        runs = data
        defaults: Dict[str, Any] = {}
    elif isinstance(data, dict):
        runs = data.get("runs")
        if not isinstance(runs, list):
            raise ValueError("JSON object must include a 'runs' list")
        defaults = {k: v for k, v in data.items() if k != "runs"}
    else:
        raise ValueError("Parameter file must be a list or object with 'runs'")
    for idx, entry in enumerate(runs):
        if not isinstance(entry, dict) or "params" not in entry:
            raise ValueError(f"Run entry {idx} must be an object with a 'params' dict")
    return runs, defaults


def coalesce(*values: Optional[Any], default: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return default


def as_path(value: Optional[Path], fallback: Path) -> Path:
    if value is None:
        return fallback
    return Path(value)


def main() -> None:
    args = parse_args()

    if args.param_file:
        run_definitions, json_defaults = load_runs_from_json(args.param_file)
    else:
        run_definitions = [{"label": "baseline", "params": BASELINE_PARAMS}]
        json_defaults = {}

    vin = coalesce(args.vin, json_defaults.get("vin"), default=DEFAULT_VIN)
    duration = coalesce(args.duration, json_defaults.get("duration"), default=DEFAULT_DURATION)
    can_interface = coalesce(
        args.can_interface, json_defaults.get("can_interface"), default=DEFAULT_INTERFACE
    )

    history_path = as_path(
        args.history,
        as_path(json_defaults.get("history_path"), DEFAULT_HISTORY_PATH)
        if isinstance(json_defaults.get("history_path"), (str, Path))
        else DEFAULT_HISTORY_PATH,
    )
    run_log_path = as_path(
        args.run_log,
        as_path(json_defaults.get("run_log_path"), DEFAULT_RUN_LOG_PATH)
        if isinstance(json_defaults.get("run_log_path"), (str, Path))
        else DEFAULT_RUN_LOG_PATH,
    )
    aggregate_path = as_path(
        args.aggregate,
        as_path(json_defaults.get("aggregate_path"), DEFAULT_AGGREGATE_PATH)
        if isinstance(json_defaults.get("aggregate_path"), (str, Path))
        else DEFAULT_AGGREGATE_PATH,
    )

    scpi_port = coalesce(
        args.scpi_port,
        json_defaults.get("scpi_port"),
        default=DEFAULT_SCPI_PORT,
    )
    scpi_off = coalesce(
        args.scpi_off_time,
        json_defaults.get("scpi_off_time"),
        default=DEFAULT_SCPI_OFF_TIME,
    )
    scpi_wait = coalesce(
        args.scpi_wait,
        json_defaults.get("scpi_wait"),
        default=DEFAULT_SCPI_WAIT,
    )
    scpi_disabled = args.no_scpi or bool(json_defaults.get("no_scpi", False))

    base_controller: Optional[SCPIPowerController] = None
    if not scpi_disabled and scpi_port:
        base_controller = SCPIPowerController(
            scpi_port,
            off_time=scpi_off,
            wait_before_activation=scpi_wait,
        )

    for index, run_def in enumerate(run_definitions):
        params = run_def.get("params")
        if not isinstance(params, dict):
            raise ValueError(f"Run definition {index} missing parameter dictionary")

        label = run_def.get("label") or run_def.get("name")
        if not label:
            prefix = args.label_prefix or "run"
            label = f"{prefix}-{index:03d}"

        run_duration = coalesce(run_def.get("duration"), default=duration)
        run_vin = run_def.get("vin") or vin
        run_interface = run_def.get("can_interface") or can_interface
        run_id = run_def.get("run_id") or run_def.get("id")

        run_no_scpi = scpi_disabled or bool(run_def.get("no_scpi", False))
        controller = base_controller
        if run_no_scpi:
            controller = None
        else:
            override_port = run_def.get("scpi_port")
            override_off = run_def.get("scpi_off_time")
            override_wait = run_def.get("scpi_wait")
            if override_port or override_off or override_wait:
                controller = SCPIPowerController(
                    override_port or scpi_port,
                    off_time=coalesce(override_off, default=scpi_off),
                    wait_before_activation=coalesce(override_wait, default=scpi_wait),
                )

        metadata_extra = run_def.get("metadata")
        if metadata_extra is not None and not isinstance(metadata_extra, dict):
            raise ValueError(f"Run definition {index} metadata must be a dict if provided")
        record = run_gateway_probe(
            params,
            vin=run_vin,
            interface=run_interface,
            duration_s=run_duration,
            power_controller=controller,
            run_log_path=run_log_path,
            run_id=run_id,
            label=label,
            source="scan_gateway_env",
            metadata_extra=metadata_extra,
        )

        entry = build_history_entry(
            record,
            params,
            label=label,
            duration_s=run_duration,
            notes=run_def.get("notes"),
        )
        append_history_entry(history_path, entry)

        base_codes = record.get("error_base_codes_hex") or []
        vin_complete = record.get("vin_complete")
        init_messages = record.get("init_messages", 0)
        print(
            f"[{label}] run_id={record.get('run_id')} base_codes={base_codes or ['none']} "
            f"vin_complete={vin_complete}/7 has_0x631={bool(init_messages)}"
        )

    update_aggregate_from_history(history_path, aggregate_path)
    print(f"History appended to {history_path}")
    print(f"Aggregate updated at {aggregate_path}")


if __name__ == "__main__":
    main()
