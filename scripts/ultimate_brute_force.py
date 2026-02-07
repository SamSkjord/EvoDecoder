#!/usr/bin/env python3
"""
Ultimate Brute Force: Tesla Radar Activation Parameter Search

Systematically finds the exact CAN parameter combination that activates a
Bosch MRRevo14F radar from a Tesla Model S.  Uses a phased approach with
intelligent pruning to minimise the search space.

Usage:
    DYLD_LIBRARY_PATH=/opt/homebrew/opt/libusb/lib \
        python3 scripts/ultimate_brute_force.py --phase all
"""

import argparse
import itertools
import json
import os
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.activation.tesla_radar_activator import SCPIPowerController, TeslaRadarActivator
from src.protocol.tesla_radar_protocol import setup_can
from src.utils.gateway_probe_utils import (
    apply_gateway_params,
    append_history_entry,
    build_history_entry,
    extract_protocol_kwargs,
)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_VIN = "5YJSB7E43GF113105"
DEFAULT_CAN_INTERFACE = "can0"
DEFAULT_SCPI_PORT = "/dev/cu.usbserial-2210"
DEFAULT_DURATION = 15
DEFAULT_EXTENDED_DURATION = 60
DEFAULT_HISTORY = ROOT / "data" / "probe_results" / "ubf_history.jsonl"
DEFAULT_CHECKPOINT = ROOT / "data" / "brute_force_v2_checkpoint.json"
DEFAULT_MAX_PHASE3_RUNS = 5000

# Error-bit labels (from 0x3FF byte-1 bitmask analysis)
ERROR_BIT_NAMES = {
    0x08: "VIN",
    0x10: "AIR_SUSP",
    0x20: "EPAS",
    0x40: "CHASSIS",
    0x80: "BIT7",
}


# ═══════════════════════════════════════════════════════════════════════════
# RunScorer — composite 0-100 metric
# ═══════════════════════════════════════════════════════════════════════════
class RunScorer:
    """Score a single probe run on a 0-100 scale."""

    @staticmethod
    def score(record: Dict[str, Any]) -> float:
        s = 0.0

        # --- Zero errors (30 pts) ---
        error_codes = record.get("error_codes", [])
        base_codes = record.get("error_base_codes", [])
        n_errors = len(base_codes) if base_codes else len(error_codes)
        s += 30.0 * max(0.0, 1.0 - min(n_errors, 8) / 8.0)

        # --- VIN complete (10 pts) ---
        vin_complete = record.get("vin_complete", 0) or 0
        s += 10.0 * min(vin_complete, 7) / 7.0

        # --- Has 0x631 init (5 pts) ---
        if record.get("init_messages", 0):
            s += 5.0

        # --- Has 0x300 status (5 pts) ---
        if record.get("status_messages", 0):
            s += 5.0

        # --- Dynamic scanning (20 pts) ---
        flags = record.get("success_flags", {})
        scan_stats = record.get("scan_index_stats", {})
        if flags.get("dynamic_scanning") or scan_stats.get("is_dynamic"):
            s += 20.0
        elif scan_stats.get("unique_count", 0) > 3:
            s += 10.0

        # --- Plant mode exited (15 pts) ---
        if flags.get("plant_mode_exited"):
            s += 15.0

        # --- Valid objects (10 pts) ---
        if flags.get("radar_fully_active"):
            s += 10.0

        # --- Fully active bonus (5 pts) ---
        if flags.get("radar_fully_active") and flags.get("dynamic_scanning") and flags.get("plant_mode_exited"):
            s += 5.0

        return round(s, 1)


# ═══════════════════════════════════════════════════════════════════════════
# ConstraintMap — (param, value) → error bitmask tracking
# ═══════════════════════════════════════════════════════════════════════════
class ConstraintMap:
    """Track which (param, value) pairs consistently produce error counts.

    Since the error bitmask is often identical (e.g. always 0xF8), we track
    the *number* of distinct base error codes instead — this captures the
    real signal (8 codes vs 15 codes).
    """

    def __init__(self):
        # {(param_name, value): [error_count, error_count, ...]}
        self._evidence: Dict[Tuple[str, Any], List[int]] = defaultdict(list)

    def record(self, params: Dict[str, Any], error_count: int) -> None:
        for key, value in params.items():
            self._evidence[(key, value)].append(error_count)

    def predict_min_errors(self, params: Dict[str, Any], min_evidence: int = 3) -> Optional[int]:
        """Predict the minimum error count for a param combo.

        For each (param, value) pair with enough evidence, take the minimum
        error count ever observed.  The predicted count for the full combo is
        the max of all individual minimums (the worst bottleneck).
        Returns None if insufficient evidence.
        """
        worst_min = None
        for key, value in params.items():
            samples = self._evidence.get((key, value), [])
            if len(samples) >= min_evidence:
                pair_min = min(samples)
                if worst_min is None or pair_min > worst_min:
                    worst_min = pair_min
        return worst_min

    def should_skip(self, params: Dict[str, Any], best_error_count: int, min_evidence: int = 3) -> bool:
        """Return True if the predicted error count is >= the current best."""
        predicted = self.predict_min_errors(params, min_evidence)
        if predicted is None:
            return False  # not enough evidence
        return predicted >= best_error_count

    def rebuild_from_history(self, history: List[Dict[str, Any]]) -> None:
        self._evidence.clear()
        for entry in history:
            params = entry.get("params") or (entry.get("metadata", {}) or {}).get("params", {})
            base_codes = entry.get("error_base_codes", [])
            if not base_codes:
                hex_codes = entry.get("error_base_codes_hex", [])
                base_codes = hex_codes
            self.record(params, len(base_codes))


# ═══════════════════════════════════════════════════════════════════════════
# ParameterSpace
# ═══════════════════════════════════════════════════════════════════════════
class ParameterSpace:
    """Generate parameter combinations for each phase."""

    # Fixed params that stay constant across Phase 1
    PHASE1_FIXED = {
        "GTW_performanceConfig": 2,
        "GTW_autopilot": 1,
        "GTW_country": 826,
        "GTW_rhd": 1,
    }

    PHASE1_GRID = {
        "GTW_fourWheelDrive": [0, 1],
        "GTW_airSuspensionInstalled": [0, 1, 2, 3],
        "GTW_epasType": [0, 1, 2, 3],
        "GTW_chassisType": [0, 1, 2],
        "radarEpasType": [0, 1],
        "radarPosition": [0],
    }

    PHASE2_SWEEPS = [
        ("GTW_fourWheelDrive", [0, 1]),
        ("GTW_airSuspensionInstalled", list(range(8))),
        ("GTW_epasType", [0, 1, 2, 3]),
        ("radarEpasType", [0, 1]),
        ("GTW_chassisType", list(range(4))),
        ("GTW_performanceConfig", list(range(8))),
        ("GTW_autopilot", [0, 1, 2, 3]),
        ("radarPosition", [0, 1, 2]),
    ]

    PHASE3_GRID = {
        "radarPosition": [0, 1, 2],
        "radarEpasType": [0, 1],
        "GTW_fourWheelDrive": [0, 1],
        "GTW_airSuspensionInstalled": list(range(8)),
        "GTW_epasType": list(range(4)),
        "GTW_chassisType": list(range(4)),
        "GTW_performanceConfig": list(range(8)),
        "GTW_autopilot": list(range(4)),
    }

    PHASE4_EXTRA = {
        "GTW_dasHw": [0, 1, 2, 3],
        "GTW_forwardRadarHw": [0, 1, 2, 3],
        "GTW_parkAssistInstalled": [0, 1, 2, 3],
        "GTW_bodyControlsType": [0, 1],
        "GTW_country": [826, 840, 276, 250, 0],
        "speed_kph": [0, 30, 60, 100],
    }

    @staticmethod
    def phase1_combos() -> List[Dict[str, Any]]:
        keys = list(ParameterSpace.PHASE1_GRID.keys())
        values = [ParameterSpace.PHASE1_GRID[k] for k in keys]
        combos = []
        for vals in itertools.product(*values):
            params = dict(zip(keys, vals))
            params.update(ParameterSpace.PHASE1_FIXED)
            combos.append(params)
        return combos

    @staticmethod
    def phase2_sweeps(baseline: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
        """Return a list of sweep-groups, one per parameter."""
        groups = []
        for param, values in ParameterSpace.PHASE2_SWEEPS:
            sweep = []
            for v in values:
                p = dict(baseline)
                p[param] = v
                sweep.append(p)
            groups.append(sweep)
        return groups

    @staticmethod
    def phase3_combos() -> List[Dict[str, Any]]:
        keys = list(ParameterSpace.PHASE3_GRID.keys())
        values = [ParameterSpace.PHASE3_GRID[k] for k in keys]
        combos = []
        for vals in itertools.product(*values):
            combos.append(dict(zip(keys, vals)))
        return combos

    @staticmethod
    def phase4_sweeps(baseline: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
        groups = []
        for param, values in ParameterSpace.PHASE4_EXTRA.items():
            sweep = []
            for v in values:
                p = dict(baseline)
                p[param] = v
                sweep.append(p)
            groups.append(sweep)
        return groups


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _compute_error_mask(entry: Dict[str, Any]) -> int:
    """Compute the union bitmask of all error codes in a run."""
    codes = entry.get("error_codes", [])
    if not codes:
        hex_codes = entry.get("error_codes_hex", [])
        codes = [int(h, 16) for h in hex_codes] if hex_codes else []
    mask = 0
    for c in codes:
        mask |= c
    return mask


def _mask_to_labels(mask: int) -> str:
    labels = []
    for bit, name in sorted(ERROR_BIT_NAMES.items()):
        if mask & bit:
            labels.append(name)
    if not labels:
        return "NONE"
    return ",".join(labels)


def _params_short(params: Dict[str, Any]) -> str:
    """One-line summary of the key brute-force parameters."""
    keys = [
        ("GTW_fourWheelDrive", "awd"),
        ("GTW_airSuspensionInstalled", "air"),
        ("GTW_epasType", "epas"),
        ("GTW_chassisType", "chassis"),
        ("radarPosition", "rpos"),
        ("radarEpasType", "reps"),
        ("GTW_performanceConfig", "perf"),
        ("GTW_autopilot", "ap"),
    ]
    parts = []
    for key, abbr in keys:
        if key in params:
            parts.append(f"{abbr}={params[key]}")
    return " ".join(parts)


def _load_history(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    entries = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            text = line.strip()
            if not text:
                continue
            try:
                entries.append(json.loads(text))
            except json.JSONDecodeError:
                continue
    return entries


def _save_checkpoint(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.rename(path)


def _load_checkpoint(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


# ═══════════════════════════════════════════════════════════════════════════
# BruteForceEngine
# ═══════════════════════════════════════════════════════════════════════════
class BruteForceEngine:
    """Main orchestrator for the phased brute-force search."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.vin = args.vin
        self.can_interface = args.can_interface
        self.duration = args.duration
        self.extended_duration = args.extended_duration
        self.history_path = Path(args.history)
        self.checkpoint_path = Path(args.checkpoint)

        self.scorer = RunScorer()
        self.constraints = ConstraintMap()

        # State
        self.total_runs = 0
        self.best_score = 0.0
        self.best_params: Dict[str, Any] = {}
        self.best_error_mask = 0xFF
        self.best_error_count = 999
        self.best_record: Dict[str, Any] = {}
        self.zero_error_runs: List[Dict[str, Any]] = []
        self.pruned_count = 0
        self.start_time = time.time()
        self._interrupted = False

        # Power controller
        self.power_controller: Optional[SCPIPowerController] = None
        if not args.no_scpi:
            self.power_controller = SCPIPowerController(
                args.scpi_port,
                off_time=1.5,
                wait_before_activation=3.0,
            )

        # Error-bit frequency tracking
        self.error_bit_counts: Dict[int, int] = defaultdict(int)
        self.error_bit_total = 0

        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_interrupt)

    def _handle_interrupt(self, signum, frame):
        print("\n\n>>> Interrupt received — finishing current run and saving checkpoint...")
        self._interrupted = True

    # -------------------------------------------------------------------
    # Single run execution
    # -------------------------------------------------------------------
    def _run_single(
        self,
        params: Dict[str, Any],
        run_duration: int,
        *,
        phase: str,
        phase_index: int,
        phase_total: int,
    ) -> Dict[str, Any]:
        """Execute one activation probe and return the record."""
        run_id = f"ubf-{phase}-{self.total_runs:05d}"
        bus = setup_can(interface=self.can_interface)

        try:
            proto_kwargs = extract_protocol_kwargs(params)
            activator = TeslaRadarActivator(
                bus,
                vin=self.vin,
                debug=self.args.debug,
                power_controller=self.power_controller,
                run_log_path=str(self.history_path),
                **proto_kwargs,
            )
            proto = activator.protocol
            apply_gateway_params(proto, params)

            metadata = {
                "source": "ultimate_brute_force",
                "phase": phase,
                "phase_index": phase_index,
                "phase_total": phase_total,
                "total_run": self.total_runs,
                "params": params,
            }

            # Suppress verbose output from activator
            activator.protocol.debug = self.args.debug

            record = activator.run_activation_sequence(
                duration=run_duration,
                run_id=run_id,
                metadata=metadata,
            )
            return record
        finally:
            try:
                bus.shutdown()
            except Exception:
                pass

    # -------------------------------------------------------------------
    # Process a single run result
    # -------------------------------------------------------------------
    def _process_result(self, record: Dict[str, Any], params: Dict[str, Any]) -> float:
        """Score, update constraints, update best, and return the score."""
        score = self.scorer.score(record)
        error_mask = _compute_error_mask(record)
        base_codes = record.get("error_base_codes", [])
        n_errors = len(base_codes)

        # Update constraint map with error COUNT (not mask — mask is always 0xF8)
        self.constraints.record(params, n_errors)

        # Update error-bit frequencies
        self.error_bit_total += 1
        for bit in ERROR_BIT_NAMES:
            if error_mask & bit:
                self.error_bit_counts[bit] += 1

        # Update best
        if score > self.best_score:
            self.best_score = score
            self.best_params = dict(params)
            self.best_error_mask = error_mask
            self.best_error_count = n_errors
            self.best_record = record

        # Track zero-error runs
        if not base_codes:
            self.zero_error_runs.append({
                "run_id": record.get("run_id"),
                "params": dict(params),
                "score": score,
            })

        self.total_runs += 1
        return score

    # -------------------------------------------------------------------
    # Display
    # -------------------------------------------------------------------
    def _display_result(
        self,
        params: Dict[str, Any],
        record: Dict[str, Any],
        score: float,
        *,
        phase: str,
        phase_index: int,
        phase_total: int,
    ) -> None:
        error_mask = _compute_error_mask(record)
        base_codes = record.get("error_base_codes", [])
        n_errors = len(base_codes)
        vin_complete = record.get("vin_complete", 0) or 0
        has_631 = "Yes" if record.get("init_messages", 0) else "No"
        scan_stats = record.get("scan_index_stats", {})
        scan_status = "dynamic" if scan_stats.get("is_dynamic") else f"{scan_stats.get('unique_count', '?')}uniq"
        power_samples = record.get("power_level_samples", [])
        power_val = power_samples[-1] if power_samples else "?"

        # Measure current if available
        current_str = ""
        if self.power_controller:
            current = self.power_controller.measure_current()
            if current is not None:
                current_str = f" | {current:.2f}A"

        elapsed = time.time() - self.start_time
        elapsed_min = elapsed / 60.0
        runs_per_min = self.total_runs / max(elapsed_min, 0.01)
        remaining = (phase_total - phase_index) / max(runs_per_min, 0.01)

        print(f"\n{'=' * 70}")
        print(f"ULTIMATE BRUTE FORCE | {phase} | Run {phase_index}/{phase_total} | Best: {self.best_score}/100")
        print(f"{'=' * 70}")
        print(f"Current: {_params_short(params)}")
        print(f"Result:  errors={n_errors} mask=0x{error_mask:02X} [{_mask_to_labels(error_mask)}] | score={score}")
        print(f"         VIN:{vin_complete}/7 | 0x631:{has_631} | scan:{scan_status} | power:{power_val}{current_str}")

        if self.best_params:
            print(f"Best so far: {self.best_score} | errors={self.best_error_count} mask=0x{self.best_error_mask:02X} [{_mask_to_labels(self.best_error_mask)}]")
            print(f"         params: {_params_short(self.best_params)}")

        print(f"Zero-error runs: {len(self.zero_error_runs)} | Pruned: {self.pruned_count} | Elapsed: {elapsed_min:.0f}m | ETA: {remaining:.0f}m")
        print(f"{'-' * 70}")

        # Error bit frequencies
        if self.error_bit_total > 0:
            parts = []
            for bit, name in sorted(ERROR_BIT_NAMES.items()):
                pct = 100.0 * self.error_bit_counts.get(bit, 0) / self.error_bit_total
                parts.append(f"{name}:{pct:.0f}%")
            print(f"Error bits: {' '.join(parts)}")

    # -------------------------------------------------------------------
    # Checkpoint
    # -------------------------------------------------------------------
    def _save_state(self, phase: str, phase_index: int) -> None:
        data = {
            "phase": phase,
            "phase_index": phase_index,
            "total_runs": self.total_runs,
            "best_score": self.best_score,
            "best_params": self.best_params,
            "best_error_mask": self.best_error_mask,
            "best_error_count": self.best_error_count,
            "zero_error_runs": self.zero_error_runs,
            "pruned_count": self.pruned_count,
            "saved_at": datetime.utcnow().isoformat() + "Z",
        }
        _save_checkpoint(self.checkpoint_path, data)

    def _restore_state(self) -> Optional[Dict[str, Any]]:
        ckpt = _load_checkpoint(self.checkpoint_path)
        if ckpt is None:
            return None
        self.total_runs = ckpt.get("total_runs", 0)
        self.best_score = ckpt.get("best_score", 0.0)
        self.best_params = ckpt.get("best_params", {})
        self.best_error_mask = ckpt.get("best_error_mask", 0xFF)
        self.best_error_count = ckpt.get("best_error_count", 999)
        self.zero_error_runs = ckpt.get("zero_error_runs", [])
        self.pruned_count = ckpt.get("pruned_count", 0)

        # Rebuild constraint map from full history
        history = _load_history(self.history_path)
        self.constraints.rebuild_from_history(history)
        for entry in history:
            self.error_bit_total += 1
            mask = _compute_error_mask(entry)
            for bit in ERROR_BIT_NAMES:
                if mask & bit:
                    self.error_bit_counts[bit] += 1

        return ckpt

    # -------------------------------------------------------------------
    # Phase implementations
    # -------------------------------------------------------------------
    def run_phase1(self, start_index: int = 0) -> None:
        """Phase 1: Smart baseline sweep."""
        combos = ParameterSpace.phase1_combos()
        phase_total = len(combos)
        print(f"\n{'#' * 70}")
        print(f"# PHASE 1: Smart Baseline Sweep ({phase_total} combinations)")
        print(f"{'#' * 70}\n")

        for i, params in enumerate(combos):
            if i < start_index:
                continue
            if self._interrupted:
                break
            if self.args.max_runs and self.total_runs >= self.args.max_runs:
                print(f"Global max runs ({self.args.max_runs}) reached.")
                break

            # Pruning
            if self.total_runs > 10 and self.constraints.should_skip(params, self.best_error_count):
                self.pruned_count += 1
                continue

            record = self._run_single(
                params, self.duration,
                phase="phase1", phase_index=i + 1, phase_total=phase_total,
            )
            score = self._process_result(record, params)
            self._display_result(params, record, score, phase="Phase 1", phase_index=i + 1, phase_total=phase_total)
            self._save_state("phase1", i + 1)

            # Early stop conditions
            if self.args.stop_on_zero_errors and not record.get("error_base_codes"):
                print("\n>>> ZERO ERRORS — stopping as requested.")
                return
            if self.args.stop_on_active and record.get("success_flags", {}).get("radar_fully_active"):
                print("\n>>> RADAR FULLY ACTIVE — stopping as requested.")
                return

    def run_phase2(self, start_index: int = 0) -> None:
        """Phase 2: Iterative single-parameter refinement."""
        if not self.best_params:
            print("Phase 2 skipped — no Phase 1 results to refine.")
            return

        print(f"\n{'#' * 70}")
        print(f"# PHASE 2: Iterative Refinement (from best: {_params_short(self.best_params)})")
        print(f"{'#' * 70}\n")

        max_iterations = 3
        for iteration in range(max_iterations):
            if self._interrupted:
                break
            improved = False
            baseline = dict(self.best_params)
            sweep_groups = ParameterSpace.phase2_sweeps(baseline)

            flat_index = 0
            total_in_iteration = sum(len(g) for g in sweep_groups)

            for group in sweep_groups:
                for params in group:
                    flat_index += 1
                    if flat_index <= start_index and iteration == 0:
                        continue
                    if self._interrupted:
                        break
                    if self.args.max_runs and self.total_runs >= self.args.max_runs:
                        return

                    # Skip if identical to current best
                    if params == self.best_params:
                        continue

                    record = self._run_single(
                        params, self.duration,
                        phase="phase2", phase_index=flat_index, phase_total=total_in_iteration,
                    )
                    score = self._process_result(record, params)
                    self._display_result(
                        params, record, score,
                        phase=f"Phase 2 iter {iteration+1}",
                        phase_index=flat_index,
                        phase_total=total_in_iteration,
                    )
                    self._save_state("phase2", flat_index)

                    if score > self.best_score - 0.1:
                        improved = True

                    if self.args.stop_on_zero_errors and not record.get("error_base_codes"):
                        print("\n>>> ZERO ERRORS — stopping.")
                        return
                    if self.args.stop_on_active and record.get("success_flags", {}).get("radar_fully_active"):
                        print("\n>>> RADAR FULLY ACTIVE — stopping.")
                        return

            start_index = 0  # only applies to first iteration on resume
            if not improved:
                print(f"No improvement in iteration {iteration+1} — stopping Phase 2.")
                break

    def run_phase3(self, start_index: int = 0) -> None:
        """Phase 3: Full grid with pruning."""
        all_combos = ParameterSpace.phase3_combos()
        max_runs = self.args.max_phase3_runs

        print(f"\n{'#' * 70}")
        print(f"# PHASE 3: Full Grid ({len(all_combos)} raw combos, cap={max_runs})")
        print(f"{'#' * 70}\n")

        # Sort combos by predicted error count (ascending) for priority ordering
        def predicted_errors(params):
            mask = self.constraints.predict_mask(params, min_evidence=2)
            return bin(mask).count("1")

        all_combos.sort(key=predicted_errors)

        phase3_runs = 0
        for i, params in enumerate(all_combos):
            if i < start_index:
                continue
            if self._interrupted:
                break
            if phase3_runs >= max_runs:
                print(f"Phase 3 cap ({max_runs}) reached.")
                break
            if self.args.max_runs and self.total_runs >= self.args.max_runs:
                return

            # Pruning
            if self.total_runs > 20 and self.constraints.should_skip(params, self.best_error_count, min_evidence=3):
                self.pruned_count += 1
                continue

            record = self._run_single(
                params, self.duration,
                phase="phase3", phase_index=i + 1, phase_total=len(all_combos),
            )
            score = self._process_result(record, params)
            phase3_runs += 1
            self._display_result(
                params, record, score,
                phase="Phase 3", phase_index=i + 1, phase_total=len(all_combos),
            )
            self._save_state("phase3", i + 1)

            if self.args.stop_on_zero_errors and not record.get("error_base_codes"):
                print("\n>>> ZERO ERRORS — stopping.")
                return
            if self.args.stop_on_active and record.get("success_flags", {}).get("radar_fully_active"):
                print("\n>>> RADAR FULLY ACTIVE — stopping.")
                return

    def run_phase4(self, start_index: int = 0) -> None:
        """Phase 4: Extended parameters."""
        if not self.best_params:
            print("Phase 4 skipped — no baseline.")
            return

        print(f"\n{'#' * 70}")
        print(f"# PHASE 4: Extended Parameters")
        print(f"{'#' * 70}\n")

        sweep_groups = ParameterSpace.phase4_sweeps(self.best_params)
        flat_index = 0
        total = sum(len(g) for g in sweep_groups)

        for group in sweep_groups:
            for params in group:
                flat_index += 1
                if flat_index <= start_index:
                    continue
                if self._interrupted:
                    break
                if self.args.max_runs and self.total_runs >= self.args.max_runs:
                    return

                record = self._run_single(
                    params, self.duration,
                    phase="phase4", phase_index=flat_index, phase_total=total,
                )
                score = self._process_result(record, params)
                self._display_result(
                    params, record, score,
                    phase="Phase 4", phase_index=flat_index, phase_total=total,
                )
                self._save_state("phase4", flat_index)

                if self.args.stop_on_zero_errors and not record.get("error_base_codes"):
                    print("\n>>> ZERO ERRORS — stopping.")
                    return
                if self.args.stop_on_active and record.get("success_flags", {}).get("radar_fully_active"):
                    print("\n>>> RADAR FULLY ACTIVE — stopping.")
                    return

    def run_phase5(self) -> None:
        """Phase 5: Extended validation of zero-error runs."""
        if not self.zero_error_runs:
            print("\nPhase 5 skipped — no zero-error runs to validate.")
            return

        print(f"\n{'#' * 70}")
        print(f"# PHASE 5: Zero-Error Validation ({len(self.zero_error_runs)} candidates)")
        print(f"{'#' * 70}\n")

        for i, entry in enumerate(self.zero_error_runs):
            if self._interrupted:
                break
            params = entry["params"]
            print(f"\n--- Validating candidate {i+1}/{len(self.zero_error_runs)} ---")
            print(f"    Params: {_params_short(params)}")
            print(f"    Running extended test ({self.extended_duration}s)...")

            record = self._run_single(
                params, self.extended_duration,
                phase="phase5", phase_index=i + 1, phase_total=len(self.zero_error_runs),
            )
            score = self._process_result(record, params)
            self._display_result(
                params, record, score,
                phase="Phase 5 (Validation)", phase_index=i + 1, phase_total=len(self.zero_error_runs),
            )
            self._save_state("phase5", i + 1)

            flags = record.get("success_flags", {})
            if flags.get("radar_fully_active"):
                print("\n" + "=" * 70)
                print("   RADAR FULLY ACTIVE AND VALIDATED!")
                print(f"   Winning params: {_params_short(params)}")
                print(f"   Full params: {json.dumps(params, indent=2)}")
                print("=" * 70)
                return

    # -------------------------------------------------------------------
    # Main entry
    # -------------------------------------------------------------------
    def run(self) -> None:
        phase = self.args.phase
        start_index = 0

        # Resume support
        if self.args.resume:
            ckpt = self._restore_state()
            if ckpt:
                phase_from_ckpt = ckpt.get("phase", "phase1")
                start_index = ckpt.get("phase_index", 0)
                print(f"Resuming from {phase_from_ckpt} index {start_index} (total runs: {self.total_runs})")
                if phase == "all":
                    phase = phase_from_ckpt
            else:
                print("No checkpoint found — starting fresh.")

        # Ensure history directory exists
        self.history_path.parent.mkdir(parents=True, exist_ok=True)

        # Determine which phases to run
        phases_to_run = []
        if phase == "all":
            phases_to_run = ["phase1", "phase2", "phase3", "phase4", "phase5"]
        elif phase in ("1", "phase1"):
            phases_to_run = ["phase1"]
        elif phase in ("2", "phase2"):
            phases_to_run = ["phase2"]
        elif phase in ("3", "phase3"):
            phases_to_run = ["phase3"]
        elif phase in ("4", "phase4"):
            phases_to_run = ["phase4"]
        elif phase in ("5", "phase5"):
            phases_to_run = ["phase5"]

        first_phase = True
        for p in phases_to_run:
            if self._interrupted:
                break
            idx = start_index if first_phase else 0
            first_phase = False

            if p == "phase1":
                self.run_phase1(start_index=idx)
            elif p == "phase2":
                self.run_phase2(start_index=idx)
            elif p == "phase3":
                self.run_phase3(start_index=idx)
            elif p == "phase4":
                self.run_phase4(start_index=idx)
            elif p == "phase5":
                self.run_phase5()

        # Final summary
        self._print_summary()

    def _print_summary(self) -> None:
        elapsed = (time.time() - self.start_time) / 60.0
        print(f"\n{'=' * 70}")
        print(f"ULTIMATE BRUTE FORCE — FINAL SUMMARY")
        print(f"{'=' * 70}")
        print(f"Total runs:       {self.total_runs}")
        print(f"Pruned:           {self.pruned_count}")
        print(f"Elapsed:          {elapsed:.1f} min")
        print(f"Best score:       {self.best_score}/100")
        print(f"Best error mask:  0x{self.best_error_mask:02X} [{_mask_to_labels(self.best_error_mask)}]")
        print(f"Best params:      {_params_short(self.best_params)}")
        print(f"Zero-error runs:  {len(self.zero_error_runs)}")
        if self.best_params:
            print(f"\nFull best params:")
            print(json.dumps(self.best_params, indent=2))
        print(f"\nHistory:    {self.history_path}")
        print(f"Checkpoint: {self.checkpoint_path}")
        print(f"{'=' * 70}")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Ultimate Brute Force: Tesla Radar Activation Parameter Search",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--phase",
        default="all",
        choices=["all", "1", "2", "3", "4", "5", "phase1", "phase2", "phase3", "phase4", "phase5"],
        help="Start from phase (default: all)",
    )
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--max-runs", type=int, default=None, help="Global max runs")
    parser.add_argument(
        "--max-phase3-runs",
        type=int,
        default=DEFAULT_MAX_PHASE3_RUNS,
        help=f"Phase 3 cap (default: {DEFAULT_MAX_PHASE3_RUNS})",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION,
        help=f"Per-run duration in seconds (default: {DEFAULT_DURATION})",
    )
    parser.add_argument(
        "--extended-duration",
        type=int,
        default=DEFAULT_EXTENDED_DURATION,
        help=f"Zero-error validation duration (default: {DEFAULT_EXTENDED_DURATION})",
    )
    parser.add_argument(
        "--can-interface",
        default=DEFAULT_CAN_INTERFACE,
        help=f"CAN channel (default: {DEFAULT_CAN_INTERFACE})",
    )
    parser.add_argument("--vin", default=DEFAULT_VIN, help=f"Vehicle VIN (default: {DEFAULT_VIN})")
    parser.add_argument(
        "--scpi-port",
        default=DEFAULT_SCPI_PORT,
        help=f"PSU serial port (default: {DEFAULT_SCPI_PORT})",
    )
    parser.add_argument("--no-scpi", action="store_true", help="Disable power cycling")
    parser.add_argument(
        "--history",
        default=str(DEFAULT_HISTORY),
        help=f"History file (default: {DEFAULT_HISTORY})",
    )
    parser.add_argument(
        "--checkpoint",
        default=str(DEFAULT_CHECKPOINT),
        help=f"Checkpoint file (default: {DEFAULT_CHECKPOINT})",
    )
    parser.add_argument("--stop-on-zero-errors", action="store_true", help="Stop at first zero-error result")
    parser.add_argument("--stop-on-active", action="store_true", help="Stop when radar_fully_active")
    parser.add_argument("--debug", action="store_true", help="Verbose CAN output")

    args = parser.parse_args()

    print("=" * 70)
    print("  ULTIMATE BRUTE FORCE: Tesla Radar Activation Parameter Search")
    print("=" * 70)
    print(f"  VIN:           {args.vin}")
    print(f"  CAN interface: {args.can_interface}")
    print(f"  Phase:         {args.phase}")
    print(f"  Duration:      {args.duration}s per run")
    print(f"  SCPI:          {'disabled' if args.no_scpi else args.scpi_port}")
    print(f"  History:       {args.history}")
    print(f"  Resume:        {args.resume}")
    print("=" * 70)
    print()

    engine = BruteForceEngine(args)
    engine.run()


if __name__ == "__main__":
    main()
