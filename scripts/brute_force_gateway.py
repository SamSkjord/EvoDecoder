#!/usr/bin/env python3
"""
Tesla Radar Gateway Brute Force Tool

Systematically iterates through gateway configuration parameters to find
combinations that reduce or eliminate plant mode error codes.

UK-Focused Strategy:
- Priority 1: UK (826) - radar's origin country
- Priority 2: European codes - 276 (DE), 250 (FR), 380 (IT), 724 (ES)
- Priority 3: Other markets - 840 (US), 124 (CA), 36 (AU)

Parameter Space:
- Country codes: ~8 priority values
- Air suspension: 0-3 (4 values)
- EPAS type: 0-3 (4 values)
- Four-wheel drive: 0-1 (2 values)
- Chassis type: 0-3 (4 values)
- Performance config: 0-3 (4 values)
- Radar position: 0-2 (3 values)

Total combinations per country: ~1536
Estimated time: ~2 hours per country (at 5s per run)

Usage:
    # Dry run - show parameter space without executing
    python scripts/brute_force_gateway.py --dry-run

    # Start UK-focused sweep
    python scripts/brute_force_gateway.py --country 826

    # Resume from checkpoint
    python scripts/brute_force_gateway.py --resume

    # Quick scan of most likely combinations
    python scripts/brute_force_gateway.py --quick
"""
import argparse
import itertools
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.gateway_probe_utils import (
    DEFAULT_DURATION,
    DEFAULT_HISTORY_PATH,
    DEFAULT_INTERFACE,
    DEFAULT_RUN_LOG_PATH,
    DEFAULT_SCPI_OFF_TIME,
    DEFAULT_SCPI_PORT,
    DEFAULT_SCPI_WAIT,
    DEFAULT_VIN,
    append_history_entry,
    build_history_entry,
    run_gateway_probe,
    update_aggregate_from_history,
)
from src.activation.tesla_radar_activator import SCPIPowerController

# UK-focused country codes in priority order
COUNTRY_CODES = {
    # Priority 1 - UK (radar's origin)
    826: "UK",
    # Priority 2 - Major European markets
    276: "Germany",
    250: "France",
    380: "Italy",
    724: "Spain",
    # Priority 3 - Other major markets
    840: "USA",
    124: "Canada",
    36: "Australia",
}

# Parameter ranges for brute force
PARAM_RANGES = {
    "GTW_airSuspensionInstalled": [0, 1, 2, 3],
    "GTW_epasType": [0, 1, 2, 3],
    "GTW_fourWheelDrive": [0, 1],
    "GTW_chassisType": [0, 1, 2, 3],
    "GTW_performanceConfig": [0, 1, 2, 3],
    "radarPosition": [0, 1, 2],
    "radarEpasType": [0, 1],
}

# Quick scan: most likely combinations based on P90D UK spec
QUICK_SCAN_PARAMS = {
    "GTW_airSuspensionInstalled": [3, 2, 1],  # Most likely: 3 (installed)
    "GTW_epasType": [1, 0, 2],  # Most likely: 1 (Bosch L538)
    "GTW_fourWheelDrive": [1],  # P90D is AWD
    "GTW_chassisType": [1, 0],  # Most likely: 1 (Model S)
    "GTW_performanceConfig": [2, 1, 3],  # Most likely: 2 (performance)
    "radarPosition": [0, 1],  # Pre-facelift vs post-facelift
    "radarEpasType": [0],  # Bosch L538
}

# Checkpoint file for resume capability
CHECKPOINT_FILE = PROJECT_ROOT / "data" / "brute_force_checkpoint.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="UK-Focused Gateway Parameter Brute Force Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Mode selection
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Show parameter space without executing")
    mode.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    mode.add_argument("--quick", action="store_true", help="Quick scan of most likely combinations")

    # Country selection
    parser.add_argument(
        "--country",
        type=int,
        default=826,
        help=f"Country code to start with (default: 826=UK). Options: {list(COUNTRY_CODES.keys())}",
    )
    parser.add_argument(
        "--all-countries",
        action="store_true",
        help="Iterate through all priority country codes",
    )

    # Hardware options
    parser.add_argument("--vin", default=DEFAULT_VIN, help="Vehicle VIN")
    parser.add_argument("--can-interface", default=DEFAULT_INTERFACE, help="CAN interface name")
    parser.add_argument("--duration", type=float, default=4.0, help="Activation duration per run")

    # SCPI options
    parser.add_argument("--scpi-port", default=DEFAULT_SCPI_PORT, help="SCPI serial port")
    parser.add_argument("--scpi-off-time", type=float, default=DEFAULT_SCPI_OFF_TIME, help="SCPI off duration")
    parser.add_argument("--scpi-wait", type=float, default=DEFAULT_SCPI_WAIT, help="SCPI wait duration")
    parser.add_argument("--no-scpi", action="store_true", help="Disable SCPI power cycling")

    # Output options
    parser.add_argument(
        "--history",
        type=Path,
        default=PROJECT_ROOT / "data" / "probe_results" / "brute_force_history.jsonl",
        help="History JSONL path",
    )
    parser.add_argument(
        "--run-log",
        type=Path,
        default=DEFAULT_RUN_LOG_PATH,
        help="Run log path",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    # Filter options
    parser.add_argument(
        "--stop-on-success",
        action="store_true",
        help="Stop when no error codes are returned",
    )
    parser.add_argument(
        "--max-runs",
        type=int,
        help="Maximum number of runs before stopping",
    )

    return parser.parse_args()


def generate_combinations(
    country_code: int,
    param_ranges: Dict[str, List[int]],
    rhd: int = 1,
) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Generate all parameter combinations for a given country code."""
    keys = list(param_ranges.keys())
    values = [param_ranges[k] for k in keys]

    for combo in itertools.product(*values):
        params = dict(zip(keys, combo))
        params["GTW_country"] = country_code
        params["GTW_rhd"] = rhd

        # Generate a unique label
        label_parts = [f"c{country_code}"]
        label_parts.append(f"air{params['GTW_airSuspensionInstalled']}")
        label_parts.append(f"epas{params['GTW_epasType']}")
        label_parts.append(f"awd{params['GTW_fourWheelDrive']}")
        label_parts.append(f"chas{params['GTW_chassisType']}")
        label_parts.append(f"perf{params['GTW_performanceConfig']}")
        label_parts.append(f"rpos{params['radarPosition']}")
        label_parts.append(f"reps{params['radarEpasType']}")

        label = "_".join(label_parts)
        run_id = f"bf_{label}"

        yield run_id, params


def count_combinations(param_ranges: Dict[str, List[int]]) -> int:
    """Count total combinations for parameter ranges."""
    count = 1
    for values in param_ranges.values():
        count *= len(values)
    return count


def load_checkpoint() -> Optional[Dict[str, Any]]:
    """Load the last checkpoint if it exists."""
    if CHECKPOINT_FILE.exists():
        try:
            return json.loads(CHECKPOINT_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None


def save_checkpoint(
    country_code: int,
    run_index: int,
    total_runs: int,
    completed_countries: List[int],
    last_run_id: str,
) -> None:
    """Save checkpoint for resume capability."""
    CHECKPOINT_FILE.parent.mkdir(parents=True, exist_ok=True)
    checkpoint = {
        "timestamp": datetime.utcnow().isoformat(),
        "country_code": country_code,
        "run_index": run_index,
        "total_runs": total_runs,
        "completed_countries": completed_countries,
        "last_run_id": last_run_id,
    }
    CHECKPOINT_FILE.write_text(json.dumps(checkpoint, indent=2))


def main() -> int:
    args = parse_args()

    # Determine parameter ranges
    if args.quick:
        param_ranges = QUICK_SCAN_PARAMS
        print("Quick scan mode: using most likely parameter combinations")
    else:
        param_ranges = PARAM_RANGES

    # Determine country codes to sweep
    if args.all_countries:
        country_codes = list(COUNTRY_CODES.keys())
    else:
        country_codes = [args.country]

    # Calculate total combinations
    combos_per_country = count_combinations(param_ranges)
    total_combos = combos_per_country * len(country_codes)

    print("=" * 70)
    print("Tesla Radar Gateway Brute Force Tool")
    print("=" * 70)
    print(f"Country codes: {[f'{c} ({COUNTRY_CODES.get(c, '?')})' for c in country_codes]}")
    print(f"Combinations per country: {combos_per_country}")
    print(f"Total combinations: {total_combos}")
    print(f"Estimated time: {total_combos * args.duration / 60:.1f} minutes")
    print("=" * 70)

    if args.dry_run:
        print("\nParameter space preview:")
        for country in country_codes:
            print(f"\n--- Country {country} ({COUNTRY_CODES.get(country, '?')}) ---")
            for i, (run_id, params) in enumerate(generate_combinations(country, param_ranges)):
                if i >= 10:
                    print(f"  ... and {combos_per_country - 10} more")
                    break
                print(f"  {run_id}")
        return 0

    # Setup power controller
    power_controller = None
    if not args.no_scpi and args.scpi_port:
        power_controller = SCPIPowerController(
            args.scpi_port,
            off_time=args.scpi_off_time,
            wait_before_activation=args.scpi_wait,
        )

    # Resume logic
    start_country_idx = 0
    start_run_idx = 0
    completed_countries: List[int] = []

    if args.resume:
        checkpoint = load_checkpoint()
        if checkpoint:
            print(f"Resuming from checkpoint: {checkpoint['last_run_id']}")
            start_country_idx = country_codes.index(checkpoint["country_code"]) if checkpoint["country_code"] in country_codes else 0
            start_run_idx = checkpoint["run_index"]
            completed_countries = checkpoint.get("completed_countries", [])
        else:
            print("No checkpoint found, starting fresh")

    # Ensure output directory exists
    args.history.parent.mkdir(parents=True, exist_ok=True)

    # Main brute force loop
    run_count = 0
    success_count = 0
    best_result = None
    best_error_count = float("inf")

    try:
        for country_idx, country_code in enumerate(country_codes[start_country_idx:], start=start_country_idx):
            if country_code in completed_countries:
                continue

            country_name = COUNTRY_CODES.get(country_code, "Unknown")
            print(f"\n{'='*70}")
            print(f"Country: {country_code} ({country_name})")
            print(f"{'='*70}")

            combinations = list(generate_combinations(country_code, param_ranges))

            for run_idx, (run_id, params) in enumerate(combinations):
                if country_idx == start_country_idx and run_idx < start_run_idx:
                    continue

                run_count += 1

                if args.max_runs and run_count > args.max_runs:
                    print(f"\nMax runs ({args.max_runs}) reached")
                    return 0

                print(f"\n[{run_count}/{total_combos}] {run_id}")
                print(f"  Params: {params}")

                try:
                    record = run_gateway_probe(
                        params,
                        vin=args.vin,
                        interface=args.can_interface,
                        duration_s=args.duration,
                        power_controller=power_controller,
                        run_log_path=args.run_log,
                        run_id=run_id,
                        label=run_id,
                        source="brute_force_gateway",
                        metadata_extra={"country_name": country_name, "brute_force": True},
                    )

                    # Log result
                    entry = build_history_entry(record, params, label=run_id, duration_s=args.duration)
                    append_history_entry(args.history, entry)

                    # Analyze result
                    error_codes = record.get("error_base_codes_hex", [])
                    error_count = len(error_codes)
                    vin_complete = record.get("vin_complete", 0)
                    has_631 = bool(record.get("init_messages", 0))

                    print(f"  Result: errors={error_count}, vin={vin_complete}/7, has_0x631={has_631}")
                    if error_codes:
                        names = record.get("error_base_codes_names", {})
                        for code in error_codes[:3]:
                            print(f"    - {code}: {names.get(code, '?')}")
                        if len(error_codes) > 3:
                            print(f"    ... and {len(error_codes) - 3} more")

                    # Track best result
                    if error_count < best_error_count:
                        best_error_count = error_count
                        best_result = (run_id, params, error_codes)
                        print(f"  *** NEW BEST: {error_count} errors ***")

                    # Check for success
                    if error_count == 0:
                        success_count += 1
                        print("  *** SUCCESS: NO ERROR CODES! ***")
                        if args.stop_on_success:
                            print(f"\nStopping on success. Winning params: {params}")
                            return 0

                except Exception as e:
                    print(f"  ERROR: {e}")
                    if args.debug:
                        import traceback
                        traceback.print_exc()

                # Save checkpoint
                save_checkpoint(
                    country_code,
                    run_idx + 1,
                    combos_per_country,
                    completed_countries,
                    run_id,
                )

            # Mark country as complete
            completed_countries.append(country_code)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        print(f"Progress saved to checkpoint. Use --resume to continue.")

    finally:
        # Print summary
        print("\n" + "=" * 70)
        print("Summary")
        print("=" * 70)
        print(f"Total runs: {run_count}")
        print(f"Successful runs (no errors): {success_count}")
        if best_result:
            run_id, params, errors = best_result
            print(f"Best result: {run_id}")
            print(f"  Errors: {len(errors)}")
            print(f"  Params: {json.dumps(params, indent=4)}")

        # Update aggregate
        try:
            aggregate_path = args.history.with_suffix(".json")
            update_aggregate_from_history(args.history, aggregate_path)
            print(f"Aggregate updated: {aggregate_path}")
        except Exception as e:
            print(f"Failed to update aggregate: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
