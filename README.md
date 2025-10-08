# EvoDecoder

## Gateway Probe Workflow
- Use `scripts/scan_gateway_env.py --param-file runs.json` to replay explicit gateway environments. Each run logs to `radar_run_history.jsonl`, appends a row to `gateway_probe_history.jsonl`, and refreshes `gateway_probe_results.json` with baseline deltas.
- Use `scripts/probe_parameters.py` for single-parameter sweeps. Default sweeps match the Model S AP1 values from `references/TMS_2016_LOGS/drive6_stopanggo_clean.csv`; pass `--config` to override baseline, sweeps, or to drive custom runs.
- Both scripts honour `--vin`, `--duration`, `--can-interface`, and SCPI settings. Override `--history`, `--aggregate`, or `--run-log` if you need alternative storage.
- History entries include VIN completion, 0x631 presence, full 0x3FF payload sets, and the derived base-code deltas vs. baseline for fast triage.
