# EvoDecoder

Tesla Bosch MRRevo14F radar standalone activation toolkit. Reverse engineering the CAN protocol to exit plant mode and enable active scanning without a Tesla vehicle.

## Project Status

Working on getting a salvaged Model S radar (VIN `5YJSB7E43GF113105`, 2016 UK P90D) into an active tracking state on the bench. The radar initializes and completes VIN learn, but plant mode faults persist due to gateway configuration mismatches.

See [docs/PROGRESS_LOG.md](docs/PROGRESS_LOG.md) for current status.

## Repository Structure

```
src/                          # Core Python package
  protocol/                   # Tesla CAN protocol emulator
    tesla_radar_protocol.py   # Full gateway/ESP/EPAS frame synthesis
  activation/                 # Radar activation logic
    tesla_radar_activator.py  # Main activation runner with SCPI control
  diagnostics/                # Diagnostic utilities
    radar_flasher.py          # VIN learn and parameter tools
    read_radar_vin.py         # UDS VIN/status reader
    uds_can.py                # ISO-TP/UDS implementation
  utils/                      # Shared utilities
    gateway_probe_utils.py    # Probe result handling

scripts/                      # Entry points
  activate_radar.py           # Main activation script
  brute_force_gateway.py      # Systematic gateway parameter sweep
  probe_parameters.py         # Single-parameter sweeps
  scan_gateway_env.py         # Gateway environment replay

dbc/                          # CAN database files
  tesla_can.dbc               # Tesla vehicle CAN signals
  tesla_radar.dbc             # Radar-specific signals

docs/                         # Documentation
  README.md                   # Detailed technical notes
  PROTOCOL_REFERENCE.md       # CAN protocol reference
  BRUTE_FORCE_STRATEGY.md     # Parameter sweep strategy
  PROGRESS_LOG.md             # Work log
  PLANT_MODE_FAILURE_CODES.md # 0x3FF fault code reference

data/probe_results/           # Probe run results
archive/                      # Legacy code and logs
references/                   # External resources and captures
```

## Quick Start

### Hardware Setup

- Raspberry Pi with WaveShare dual CAN HAT (socketcan)
  - Pi CAN0 = Radar CAN1
  - Pi CAN1 = Radar CAN2
- SCPI-controlled power supply (optional, for automated power cycling)

### Basic Activation

```bash
# Copy script to Pi and run
scp scripts/activate_radar.py pi@192.168.199.200:~/
ssh pi@192.168.199.200 "python3 activate_radar.py --vin 5YJSB7E43GF113105 --duration 30"
```

### Brute Force Gateway Sweep

```bash
# Dry run to preview parameter space
python scripts/brute_force_gateway.py --dry-run

# Start UK-focused sweep (priority country code 826)
python scripts/brute_force_gateway.py --country 826
```

## Key References

- [Tinkla Tesla Radar Guide](https://tinkla.us/index.php/Tesla_Bosch_Radar_EON)
- [BogGyver OpenPilot Tesla Fork](https://github.com/BogGyver/openpilot/tree/tesla_0.6.6/selfdrive/car/tesla)
- [Tesla CAN DBC Files](https://github.com/BogGyver/opendbc/tree/tesla_unity_dev)

## Documentation

- [docs/README.md](docs/README.md) - Detailed technical notes and bench status
- [docs/PROTOCOL_REFERENCE.md](docs/PROTOCOL_REFERENCE.md) - CAN message reference
- [docs/BRUTE_FORCE_STRATEGY.md](docs/BRUTE_FORCE_STRATEGY.md) - Gateway parameter sweep approach
