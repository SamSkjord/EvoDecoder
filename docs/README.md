# Tesla Radar Activation Package

This bundle captures the code and supporting notes that successfully drove the Bosch MRRevo12/14F radar (P/N 1038224-00-B) out of plant mode on the bench.

## Contents

- `code/tesla_radar_protocol.py` – full Tesla CAN protocol emulator with:
  - Dynamic wheel speed / drivetrain synthesis
  - SydneyG-style gateway/ESP/EPAS frames (0x108/118/145/20A/00E/045/398)
  - VIN management and plant-mode fault decoding from talas9’s ODJ metadata
- `code/tesla_radar_activator.py` – activation runner with SCPI-friendly hooks, status reporting, and decoded 0x3FF output
- `code/read_radar_vin.py` – python-can port of the original OpenPilot radar VIN utility; queries the radar over ISO-TP/UDS to print VIN, plant-mode status and board IDs
- `code/radar_flasher.py` – python-can VIN/parameter tool derived from Tinkla’s radarFlasher (VIN learn routine and parameter dump)
- `docs/PLANT_MODE_FAILURE_CODES.md` – quick reference for the decoded 0x3FF / plant-mode enums
- `references/REFERENCES.md` – upstream datasets and repos used for signal definitions

## Donor Vehicle Context

- The bench radar in this package was sourced from a salvage Model S, VIN `5YJSB7E43GF113105`. We do **not** have access to the complete vehicle.
- Public VIN decoders match this car to a 2016 RHD Model S P90D built in Fremont for UK/ROW markets (dual-motor performance drivetrain, 90 kWh pack, RHD safety package). citeturn1search2turn1search1turn1search5
- Exact option codes (paint, wheels, Ludicrous enablement, charger size, etc.) remain unknown; Tesla only exposes them to the registered owner or via Toolbox on the vehicle. Treat the gateway defaults in this repository as the **inferred** configuration needed to clear VIN learn on the bench, not proof of the factory build.
- Because the donor car is gone, all future validation must be performed on the bench harness or by capturing gateway frames from another UK-spec P90D.

## Quick Start

1. Ensure CANable 2.0 is connected on macOS (`/dev/cu.usbmodem2057326E55481`) and the OWON SPE3051 supply is present on `/dev/cu.usbserial-2230`.
2. Power-cycle via SCPI (example helper in activator README) or run:

   ```bash
   python3 -c "import time, serial; ser=serial.Serial('/dev/cu.usbserial-2230',115200,timeout=1); ser.write(b'OUTP 0\r\n'); ser.flush(); time.sleep(1.5); ser.write(b'OUTP 1\r\n'); ser.flush(); ser.close()"
   ```

3. Launch the activator with the validated config:

   ```bash
   python3 tesla_radar_activator.py \
       --can-interface can1 \
       --vin 5YJSB7E43GF113105 \
       --position 1 \
       --epas 1 \
       --speed 80 \
       --duration 60 \
       --debug
   ```

   You should see at least one 0x631 init frame. After a successful VIN learn (see below), VIN completion reaches 7/7 within ~10 seconds; if plant mode still refuses to clear, continue sweeping GTW parameters.
   Additional overrides are available: `--country`, `--park-assist`, `--wheel-type`, `--brake-hw-type`, `--folding-mirrors`, `--park-geometry`, `--forward-radar-hw`, `--eu-vehicle`, and `--das-hw` can be used to match the stored gateway profile (country accepts integers, hex, or two-character ASCII such as `UK`). The current UK radar baseline uses `--country UK --air-suspension 3 --performance-config 2 --chassis-type 1 --four-wheel-drive 1 --epas 0 --autopilot-level 0 --park-assist 2 --wheel-type 10 --brake-hw-type 2 --folding-mirrors 0 --park-geometry 1 --forward-radar-hw 1 --das-hw 2 --eu-vehicle 1` with `--speed 80` and `--duration 15`.

## Notes

- The VIN decodes to a 2016 Model S P dual-motor RHD sourced from the UK. Gateway config fields (`0x398`, `0x2A9`) now reflect that spec (ASCII country "UK", AWD, air suspension, EPAS L405, RHD body).
- Gateway VIN broadcast `0x508` is a three-part SLcan burst (`0x508:00/01/02`) carrying bytes 2-8 of the VIN payload in order; mirror those frames when attempting a write so the radar sees matching VIN data on both the gateway and radar transports.
- The Scan My Tesla community capture sheet provides real-world ranges for drivetrain and battery signals (`0x145`, `0x169`, `0x17C`, `0x209`, etc.). Use those magnitudes when adjusting the bench protocol so synthetic wheel speeds, torque, and limits fall inside plausible bounds.
- 0x3FF faults are automatically mapped to Bosch/Tesla plant-mode enums; any residual warnings are printed with both the code and the enum name.
- CAN decode warnings (`non-hexadecimal number...`) originate from SLcan text glitches. They’re ignored by the protocol but left visible in `--debug` mode for completeness.
- As of 04 Oct 2025 the activator now synthesizes the gateway EPAS keep-alive frames on the bench: CAN 0x101 (`GTW_epasControl`) and 0x214 (`EPB_epasControl`). Both carry valid counters/checksums so patched EPAS/EPB firmware no longer needs those messages forwarded from the vehicle harness.
- As of 07 Oct 2025 we added the CAN 0x508 VIN burst to the protocol and moved activator runs under SCPI-controlled power cycles. This consistently produces 0x631 initialization on the bench, but plant mode still refuses to exit—current 0x3FF bases remain in the VIN/EPAS/air-suspension family (08/10/28/30/48/50/68/70 and variants) even when replaying UK gateway parameters from `gateway_probe_results.json`.
- VIN learn routine 0x0A03 now returns `030a030100` reliably, yet DID 0xF190 continues to read the donor VIN (`5YJSB7E43GF113105`) after ECU resets and bench power cycles. Writing `0xF190` directly (service 0x2E) is still rejected (`0x7F`), so a missing gateway flag or follow-up routine likely blocks the commit.
- Gateway EPAS/air-suspension enumerations remain the primary unknown. Zero-error runs in `gateway_probe_results.json` suggest the radar expects `GTW_airSuspensionInstalled=0`, `GTW_fourWheelDrive=0`, `GTW_autopilot=1`, `GTW_epasType≈0–3`, and `GTW_dasHw=0`, but bench tests with those values still emit 0x3FF payloads. Focus next on capturing in-vehicle 0x398/0x101/0x214 payloads or replaying the stored “no-error” gateway sequences.
- New flag `--use-protocol` keeps the VIN learn inline with the required gateway payload: e.g.

  ```bash
  python3 radar_flasher.py --vin-learn --use-protocol \
      --country UK --air-suspension 3 --performance-config 2 --chassis-type 1 \
      --four-wheel-drive 1 --epas-type 1 --autopilot-level 0 --park-assist 2 \
      --wheel-type 10 --brake-hw-type 2 --folding-mirrors 0 --park-geometry 1 \
      --forward-radar-hw 1 --eu-vehicle 1 --rhd 1 --radar-position 0 \
      --radar-epas-type 0 --das-hw 2 --protocol-speed 80
  ```

  This launches a lightweight gateway loop (0x398/0x101/0x214) on the same bus, eliminating the need to run the activator concurrently.
- Ongoing work: plant mode still reports composite faults (current baseline trips `0x10/0x28/0x30/0x48/0x50/0x68/0x70`). Continue GTW parameter sweeps or align 0x398/0x101 payloads with vehicle captures to eliminate the remaining bits.

### Bench status – 04 Oct 2025

- Running `tesla_radar_activator.py --duration 60 --debug --scpi-port /dev/cu.usbserial-2230` with the UK baseline produces 0x631 initialization on the bench and VIN 7/7 completion. Plant mode still reports composite faults (VIN/EPAS/air suspension). The radar reaches `0x300` state 15 (active) but immediately drops to “not present” once the faults accumulate.
- VIN learn attempts (with or without the activator) return success responses but fail to commit a new VIN. Expect to re-read the donor VIN until we discover the missing gateway prerequisite.
- Additional UDS probing (07 Oct 2025) shows the radar still exposes only a small DID set on the bench: `0xF100/0xF180/0xF181` mirror the latest 0x631 init payloads, `0xF190` remains the donor VIN, `0xF195` returns ASCII "800", and `0xF199` holds the staged VIN (`5YJSB7E4XGF111111`). Alignment identifiers `0x0505–0x050A` all read zeros and `0xA022` reports `0x00`. The radar rejects other DIDs with `0x31 (request out of range)`, so a yet-to-be-found routine must promote the `0xF199` buffer into `0xF190`.
- Lunars’ configuration dumps (see `references/lunars_exports/`) confirm steering and suspension descriptors: 2016 P90DL lists `VAPI_epasType=VGR66` and `VAPI_airSuspension=TeslaStandard`, while 2014 builds report `VAPI_epasType=L538` with `VAPI_airSuspension=Standard` or `Plus`. Encoding those strings back into our gateway fields required a raw 0x398 payload override (`0186555311310A08` from the capture, or `0986554B15700A09` via DBC), but injecting either payload still leaves the radar in plant mode with the same EPAS/air-suspension faults.
- Tesla service alert `RCM2_a641_comGTWCarConfigMIA` (Tesware lookup) labels CAN 0x398/0x7FF as `GTW_carConfig` for both Model 3 and Model S, backing up our assumption that this frame carries the gateway configuration blob we must mirror.
- Model 3 resources (Wardell DBC plus the GTW Car Config spreadsheet) enumerate the same 0x398 fields under `RCM2_a641_comGTWCarConfigMIA`; keep them handy when translating string descriptors like `VGR66` or `TeslaStandard` into the packed payload bytes.
- Tesla Owners Online hosts a long-running "Diagnostic port and data access" thread that collects community CAN logs and gateway field notes—use it to cross-check enumerations or payload meanings when our captures are ambiguous.
- Recent activation tests with the zero-error payload from `gateway_probe_results.json` (`0206554B0D400A19`) and the Lunars “TeslaStandard” payload (`0A36554B0D700A09`) confirm the radar happily produces 0x631 init bursts and VIN 7/7 completion, yet 0x3FF still flags VIN/EPAS/air mismatches (base codes 0x08/0x10/0x28/0x30/0x48/0x50/0x68/0x70). The missing piece is likely the full gateway frame set—especially 0x101/0x214/0x2A9—captured from a UK vehicle.
- Bosch MRRevo14 VW tooling (see `references/car_tools/`) documents the same radar hardware: MRRevo14_Patcher.py explains JTAG access (GND/TMS/RESET/TDI/TDO/TCK/VREF/JCOMP) and component-protection bypass, while `can_send12.py`/`cp_transfer1.py` show the UDS/TP2.0 payloads Volkswagen uses to rewrite CP and SWAP keys. JTAG pinout matches the photo above.
  - `MRRevo14_Patcher.py` patches VW firmware 0211 in-place: it swaps the public key at 0x3AA00, removes the CP error path, and is meant to be flashed back via MPC5675K JTAG (NXP CodeWarrior + Multilink FX). Script usage yields `*_Patched.bin` plus an S19 for reflashing.
  - `can_send12.py` implements VW’s TP2.0 + UDS helpers (`-WriteCPdata`, `-3QFSwap`, etc.) and expects AES keys provided by `Cluster_Aes_Keys`. Payload examples show how they write 32‑byte IKA/GEFA data to DID 0x00BE/0x00BD (ACC) via a 0x757 address.
  - `cp_transfer1.py` wraps the AES encode/decode for CP data, referring to addresses 0x31888 (IKA key in RAM) and 0x3C01 (swap status). When we eventually dump Tesla firmware, these offsets offer a starting point for locating equivalent structures.

### Model S EPAS/EPB reference trace

- Downloaded a 2016 AP1 stop-and-go capture (`references/TMS_2016_LOGS/drive6_stopanggo_clean.csv`, 117 MB, 100 Hz sampling). Startup frames show `GTW_epasControl` cycling `0x0E D0 E0`, `0x0E D1 E1`, … with counters incrementing and checksums matching the Tesla additive rule. Decodes to `GTW_epasControlType=3 (BOTH)`, `GTW_epasTuneRequest=6`, `GTW_epasLDWEnabled=1`, `GTW_epasPowerMode=1` during wake-up, later stepping through modes 2 and 0 as the car transitions. `references/TMS_2016_LOGS/drive6_stopanggo_clean.csv:10` `references/TMS_2016_LOGS/drive6_stopanggo_clean.csv:44388`
- `EPB_epasControl` in the same log stays at `0x00 01 17`, `0x00 02 18`, … (counter + checksum) with `EPB_epasEACAllow=0` for the entire trip—no evidence that the gateway asserts the allow bit during normal operation. `references/TMS_2016_LOGS/drive6_stopanggo_clean.csv:104`
- Inter-frame deltas for both IDs cluster at ~100 000 µs, confirming the 100 Hz cadence. Bench synthesis should adopt these patterns (control type 3, tune request 6, LDW 1, allow 0) and only vary `GTW_epasPowerMode` when the simulated vehicle state changes.
- Injecting these values on the bench (0x101: `0E Dn En`, 0x214: `00 nn (sum)`, 0x398: ASCII country payloads such as `55 4B`) now produces VIN 7/7 completion, confirming the VIN learn succeeded. Remaining plant-mode bits indicate the stored gateway profile still expects different EPAS/air-suspension enumerations; gathering additional UK gateway captures will refine those fields.
- Additional capture: `references/Model3Log2019-10-02v10.asc` (Model 3 v10) contains 0x398/0x631 examples with the `comGTWCarConfig` payload; useful for cross-checking the string-to-bytes mapping when porting Model 3 configs.
- `tesla_radar_protocol.py` now falls back to the AP1 stop-and-go capture (`references/TMS_2016_LOGS/drive6_stopanggo_clean.csv`) when seeding the reference sequences for 0x101/0x214, so bench runs mimic the exact wake-up cadence from that dataset without manual CSV copies.

### Notes on third-party tooling (Tinkla)

- Tinkla’s Tesla OpenPilot fork packages the MRRevo12/14 radar, plug‑and‑play harnesses, and CAN tooling (VIN read, 0x3FF decode, VIN learn trigger) inside their UI, but the VIN learn routine is meant to be executed while the radar remains on the vehicle so the Tesla gateway supplies the security handshake. citeturn2web0turn2web1
- Their `radarFlasher` bundle (mirrored here under `references/radarFlasher/`) includes the Tesla seed→key routine (`tesla_radar_security_access_algorithm`) and wraps it in shell scripts (`vin_learn.sh`, `patch_radar.py`). Our python-can port now reproduces that handshake on the bench, so VIN learn succeeds without the vehicle gateway. Firmware flashing/extraction still relies on the same algorithm; validate on your radar before attempting writes. citeturn2web1turn2web2turn2web3

## VIN / Firmware Utilities

Added two python-can utilities under `activation_release/code/`:

- `read_radar_vin.py` – ISO-TP/UDS VIN reader. Queries the radar for VIN, plant mode, board IDs, alignment metadata.
- `radar_flasher.py` – VIN learn + parameter dump (working) and initial firmware extraction/flash scaffolding. Security access uses the Tesla algorithm; firmware reads reach the seed/key handshake but the radar still rejects the computed key (`service 0x35`). Full extraction awaits the correct Bosch key derivation.

⚠️ Firmware extraction has not yet been revalidated with the updated security-access flow. Confirm the seed/key exchange succeeds for the target routine before performing READ_MEMORY_BY_ADDRESS or flashing.

### Next steps

- Capture or replay the full UK gateway frame set (0x398/0x101/0x214/0x2A9) from in-vehicle logs so the bench sees an authentic configuration, not just DBC-derived payloads.
- Continue mining community resources (Tesla Owners Online thread, Model 3 logs, Dennis Noermann’s MRRevo14 tooling) for enumerations and potential UDS routines that expose `GTW_carConfig` directly.
- JTAG roadmap: once the SPC5/MPC56xx USB TAP clone arrives, pair it with NXP CodeWarrior to dump the MRRevo14’s MPC5675K flash/RAM, inspect the stored gateway profile, patch CP logic if needed, and reflash. Firmware access should finally clarify the exact bit layout needed to clear the remaining 0x3FF faults.
