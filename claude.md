Project:
Getting a Bosch MRRevo14F radar from a Tesla working in a standalone capacity using OpenPilot's previous work:
https://tinkla.us/index.php/Tesla_Bosch_Radar_EON
https://deepwiki.com/BogGyver/
https://github.com/BogGyver/openpilot/blob/tesla_0.6.6/selfdrive/car/tesla/radar_interface.py
https://github.com/BogGyver/openpilot/tree/tesla_0.6.6/selfdrive/car/tesla/radar_tools


We've managed to extract the VIN (5YJSB7E43GF113105) using tesla_radar_reader2.py
/resources/openpilot-tesla_unity_dev/selfdrive/car/modules/radarFlasher contains some of the openpilot code for interacting with the radar, we adapted this to get tesla_radar_reader2.py functioning

https://github.com/BogGyver/openpilot/blob/tesla_unity_dev/selfdrive/car/tesla/radar_interface.py
https://github.com/BogGyver/openpilot/blob/tesla_0.6.6/panda/board/safety/safety_teslaradar.h

We have DBC files:
https://github.com/BogGyver/opendbc/blob/tesla_unity_dev/tesla_can.dbc
https://github.com/BogGyver/opendbc/blob/tesla_unity_dev/tesla_can_pre1916.dbc
https://github.com/BogGyver/opendbc/blob/tesla_unity_dev/tesla_radar.dbc

Linked files are all in /resources/
/Users/sam/git/EvoDecoder/resources/openpilot-tesla_unity_dev/selfdrive/car/tesla
/Users/sam/git/EvoDecoder/resources/openpilot-tesla_0.6.6/selfdrive/car/tesla

============================================================
HARDWARE SETUP
============================================================

Radar: Bosch MRRevo14F (Tesla part, board P/N 10 38 224-00-B)
VIN:   5YJSB7E43GF113105 (2016 Model S, Dual Motor AWD, Fremont)

CAN Adapter: Chuangxin Tech USBCAN/CANalyst-II dual-channel USB
  CANalyst-II Channel 0 = Radar CAN1 (PRIMARY — all radar traffic here)
  CANalyst-II Channel 1 = Radar CAN2 (silent/unused so far)
  python-can interface: `canalystii` (requires `canalystii` and `pyusb` packages, plus `libusb` via homebrew)
  NOTE: pyusb needs libusb discoverable — run with `DYLD_LIBRARY_PATH=/opt/homebrew/opt/libusb/lib` if pyusb raises NoBackendError

Power Supply: SCPI-controlled bench PSU over USB serial at `/dev/cu.usbserial-2210`
  PSU current thresholds: <0.20A = off/boot, 0.25-0.35A = CAN alive but RF idle, >0.38A = actively scanning

============================================================
STATUS: RADAR FULLY ACTIVE AND TRACKING OBJECTS
============================================================

The radar is now fully operational in standalone mode:
- Continuous active scanning (64 unique scan indices, dynamic scan rotation)
- Real-time object detection with distance, speed, lateral position
- High confidence tracking (96.9% on confirmed objects)
- Sustained power draw 0.35-0.50A (never drops to idle)
- 0x501 TeslaRadarAlertMatrix is clean (no configMismatch, no plantModeActive)

Run command:
```shell
DYLD_LIBRARY_PATH=/opt/homebrew/opt/libusb/lib python3 scripts/stream_objects.py --rate 2
```

============================================================
ROOT CAUSE ANALYSIS: WHY THE RADAR WAS SHUTTING DOWN
============================================================

The radar has TWO independent shutdown mechanisms:

1. CAN TIMEOUT SLEEP (solved earlier)
   - If the radar doesn't receive CAN messages at the correct frequency, it
     goes completely silent on CAN.
   - Solution: Threaded TX architecture — the TeslaRadarProtocol sends ~30
     message types at 100Hz in a dedicated TX thread, never blocked by RX
     processing. Single-threaded approaches ALL failed because RX processing
     delayed TX enough for the radar to notice timing gaps.

2. RF SECTION POWER-DOWN (solved in this session — THE KEY FIX)
   - The radar stays alive on CAN (0x300 status messages keep flowing) but
     powers down its RF transmitter, freezing the scan index and stopping
     object detection. Power draw drops from 0.4A+ to ~0.25A.
   - ROOT CAUSE: The vehicle state simulation was cycling speed to 0 kph and
     switching gear to PARK (0x01) and REVERSE (0x02) during parts of the
     60-second driving simulation cycle. When the radar sees:
       a) Zero wheel speeds in 0x169 (ESP_wheelSpeeds)
       b) PARK gear (0x01) in 0x118 (DI_torque2)
       c) Park brake request (DI_epbParkRequest=1) in 0x118
       d) Vehicle standstill status (ESP_vehicleStandstillSts=1) in 0x145
     ...it interprets this as "vehicle is parked" and powers down the RF
     section to save energy. This is NORMAL radar behavior — a parked car
     doesn't need forward collision radar.
   - The shutdown happens ~10-15 seconds after the radar first sees these
     signals, giving a brief window of scanning before RF dies.

============================================================
THE THREE FIXES THAT SOLVED IT
============================================================

All changes in: src/protocol/tesla_radar_protocol.py

1. MINIMUM SPEED ENFORCED (never zero)
   - _update_vehicle_state() now cycles speed between 30-120 kph
   - Hard floor at 20 kph: `target_speed = max(20.0, target_speed)`
   - Initial speed set to 30 kph (was 0.0)
   - The Panda reference code sends a fixed non-zero speed; we must do the same.

2. ALWAYS IN DRIVE GEAR (no PARK/REVERSE)
   - gear_state is now always 0x04 (DRIVE)
   - Previously cycled through PARK (0x01) at end of cycle and REVERSE (0x02)
     at start — both triggered RF shutdown
   - This ensures DI_epbParkRequest=0 and ESP_vehicleStandstillSts=0 at all times

3. AWD FLAG MATCHES PANDA BEHAVIOR
   - force_awd defaults to False (was True)
   - VIN heuristic now only sets AWD for VIN[7]=='2' (matching the Panda's
     safety_teslaradar.h line 211-214 exactly)
   - Our VIN has VIN[7]='4' (check digit), so AWD is correctly NOT set
   - The 0x2A9 (GTW_carConfig) message AWD bit must match what the radar
     was configured to expect

============================================================
WHAT THE 0x3FF "ERROR" CODES ACTUALLY ARE
============================================================

The 0x3FF messages report plant mode validation status. We see 16 error codes
(0x08, 0x10, 0x28, 0x30, 0x48, 0x50, 0x68, 0x70 + same with bit 7 set).
These correspond to PLANT_MODE_FAILURE_STATUS from the RADC.odj.json:
  - Bit 1 (val 2):  COUNTRY_CODE_ERROR      — NOT present (country=826 is correct)
  - Bit 2 (val 4):  DRIVE_TRAIN_ERROR       — NOT present (drivetrain config OK)
  - Bit 3 (val 8):  VIN_ERROR               — present
  - Bit 4 (val 16): AIR_SUSPENSION_ERROR    — present
  - Bit 5 (val 32): EPAS_TYPE_ERROR         — present
  - Bit 6 (val 64): CHASSIS_TYPE_ERROR      — present

CRITICAL FINDING: These errors are COSMETIC. OpenPilot completely ignores 0x3FF.
The TeslaRadarAlertMatrix (0x501) is the REAL status indicator, and it shows
clean (only RADC_a025_ambTValidity=1, which is just ambient temperature sensor).
Changing 0x398 gateway config parameters does NOT affect these error codes —
they appear to be a mismatch between the radar's internally stored config from
factory programming and what we send, but they do NOT prevent active scanning.

The brute force approach (scripts/ultimate_brute_force.py) tested 11 different
parameter combinations and ALL produced identical 0x3FF errors. This confirmed
the errors are unrelated to the actual RF shutdown problem.

============================================================
UDS DIAGNOSTIC FINDINGS
============================================================

The radar supports UDS (Unified Diagnostic Services) on TX=0x641, RX=0x651:

Supported DIDs:
  0xF190: VIN = 5YJSB7E43GF113105 (correct, matches what we send)
  0xA022: Plant Mode = 0x00 (not active) / changes to 0x01 (passed) after protocol run
  0xF110: Vehicle Config = 0x77 (stored config byte, meaning TBD)
  0xF111: Vehicle Config = 0x07 0x01 0xFF (3 bytes, partially dynamic)
  0xF100: 0x0300271000002710 (range/threshold config)
  0xF180: Firmware metadata (18 bytes)
  0xF181: Firmware metadata (18 bytes)
  0xF186: Active session type
  0xF195: Supplier SW version = "800"
  0xF199: Staged VIN buffer (temporary, used during VIN learn)
  0x0505-0x050A: Alignment data (all zeros — radar not aligned)
  0xFC01-0xFC02: Alignment angles (both 0x0000)

Plant Mode Routine (0x0A03):
  - Controlled via UDS Service 0x31 (Routine Control)
  - Requires security access level 0x11/0x12 (seed/key algorithm in radar_flasher.py)
  - START/STOP/REQUEST_RESULTS
  - Plant mode is NOT blocking radar operation

Alignment:
  - Alignment state = 0x00 (not aligned), angles = 0x0000
  - Radar operates fine without alignment — objects are detected
  - Alignment would be needed for accurate angle/position calibration

============================================================
ARCHITECTURE
============================================================

scripts/stream_objects.py — Main radar streaming script
  - Uses TeslaRadarProtocol for TX (proven working, ~30 message types)
  - Patches monitor_radar_responses to also decode objects via make_patched_monitor()
  - Thread-safe ObjectTracker class shares data between TX, RX, and print threads
  - Architecture:
      TX thread: protocol.start() → sends at 100Hz, never blocked
      RX thread: patched monitor → receives 0x300/0x631/0x3FF + decodes objects
      Main thread: prints object table at configurable rate

src/protocol/tesla_radar_protocol.py — Core protocol implementation
  - activate_tesla_radar(): sends all messages at correct frequencies
  - _update_vehicle_state(): simulates driving (30-120 kph, always DRIVE gear)
  - send_398_message(): gateway config (10Hz) — DBC-encoded from attributes
  - send_2A9_message(): radar config (1Hz) — Panda-compatible format
  - monitor_radar_responses(): RX thread, tracks radar state machine

src/activation/tesla_radar_activator.py — Activation wrapper
  - Manages power cycling via SCPI
  - Tracks scan indices, power levels, error codes, success flags
  - Used by brute force and probe scripts

src/utils/gateway_probe_utils.py — Parameter testing utilities
  - apply_gateway_params(): sets protocol attributes from param dict
  - run_gateway_probe(): power cycle + run + capture results

scripts/psu_monitor.py — Standalone PSU current monitor
  - Polls MEAS:CURR? every 0.5s, classifies IDLE/WAKING/ACTIVE

============================================================
CAN MESSAGE REFERENCE
============================================================

Messages WE SEND to the radar (via TeslaRadarProtocol):

100Hz (every cycle):
  0x199 STW_ANGLHP_STAT  — Steering angle/status + CRC
  0x169 ESP_wheelSpeeds   — Wheel speeds (encodes vehicle speed, MUST be >0)
  0x119 DI_torque2        — Constants (radar doesn't decode speed from this)
  0x109 DI_torque1        — Motor torque + counter + checksum
  0x118 DI_torque2        — Gear state (MUST be DRIVE=0x04), vehicle speed, park brake
  0x108 DI_torque1        — Motor RPM, pedal position
  0x00E IBST_driverBrake  — Brake pressure
  0x145 ESP_145h          — ESP status (standstill flag MUST be 0)
  0x20A vacuumPump        — EPAS vacuum
  0x045 STW_ANGLHP        — Steering angle
  0x132, 0x13D, 0x175, 0x186, 0x1D8, 0x257, 0x2C1 — Reference sequences
  0x101 GTW_epasPowerMode — EPAS power mode
  0x214 EPB_epasControl   — EPB control

50Hz:
  0x159 ESP_C, 0x149 ESP_145h, 0x129 ESP_115h, 0x1A9 DI_espControl

10Hz:
  0x209 GTW_odo, 0x219 STW_ACTN_RQ, 0x17C, 0x398 GTW_carConfig

4Hz:
  0x2B9 VIP_405HS (VIN, 3 parts), 0x508 (gateway VIN frames)

1Hz:
  0x2A9 GTW_carConfig (radar-specific: AWD flag + radarPosition + radarEpasType)
  0x2D9 BC_status

Messages the RADAR SENDS to us:

  0x631 — Init/sync (triggers status transition to Initializing)
  0x300 — Status (byte[0]=state, byte[1]=scan_index, byte[2]=power_level)
  0x301 — TeslaRadarSguInfo (HW fail, sensor dirty, misalignment)
  0x302 — Additional status
  0x310-0x36E — Object data (32 objects, A+B frame pairs, stride 3)
  0x371-0x382 — Extended object data
  0x383 — Object summary
  0x3FF — Plant mode status (byte[0]=counter, byte[1]=failure_code) — COSMETIC
  0x501 — TeslaRadarAlertMatrix (52 alert flags — THE real status indicator)
  0x531 — Additional diagnostics

============================================================
OBJECT DATA FORMAT
============================================================

32 objects, each with A-frame and B-frame:
  Object N: A-frame = 0x310 + (N * 3), B-frame = 0x311 + (N * 3)
  Example: Object 0 → 0x310 (A), 0x311 (B)
           Object 1 → 0x313 (A), 0x314 (B)

DBC signals (tesla_radar.dbc):
  A-frame: LongDist (distance m), LatDist (lateral m), LongSpeed (m/s),
           LongAccel, Prob (0-100%), MeasStatus, ValidSts, Index
  B-frame: LatSpeed, Class (vehicle/pedestrian/etc), MovingState

Valid object: Prob > 0 AND (ValidSts=1 OR MeasStatus=2 OR MeasStatus=3)
Confidence levels: ghost (<12.5%), weak (12.5-50%), CONFIRMED (>50%)
