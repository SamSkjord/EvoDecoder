# Progress Log

Record of approaches tried and findings for exiting plant mode on the Tesla radar.

## Hardware Setup

- **Radar Unit**: Bosch MRR evo14 (Continental)
- **Source VIN**: 5YJSB7E43GF113105 (UK P90D)
- **CAN Interface**: SLcan adapter on macOS
- **Power Supply**: SCPI-controlled bench supply

## Summary of Attempts

### Initial Discovery (Pre-consolidation)

Over 200+ runs were performed exploring the parameter space. Key findings:

1. **VIN Protocol Working**: Radar acknowledges VIN transmission (7/7 cycles)
2. **0x631 Appearing**: Radar sends initialization messages
3. **Persistent Error Codes**: Various plant mode failure codes observed

### Error Code Patterns Observed

| Code | Description | Frequency |
|------|-------------|-----------|
| 0x02 | COUNTRY_CODE_ERROR | Very common |
| 0x20 | EPAS_TYPE_ERROR | Common |
| 0x10 | AIR_SUSPENSION_ERROR | Occasional |
| 0x40 | CHASSIS_TYPE_ERROR | Occasional |

### Parameter Sweeps Completed

#### Country Code Tests
- 826 (UK): Primary focus
- 840 (US): Tested
- ASCII "UK" interpretation: Tested (0x554B)
- Various combinations with RHD flag

#### Air Suspension Tests
- Values 0-3 tested
- Value 3 shows promise for performance models
- Combined with EPAS variations

#### EPAS Type Tests
- Values 0-3 tested
- Type 1 (Bosch L538) most likely for pre-facelift

#### Combined Parameter Sweeps
- Air/EPAS cross-product
- AWD/geometry combinations
- Performance/wheel type variations

## Key Findings

### What Works
1. CAN communication established
2. Protocol messages accepted by radar
3. VIN transmission protocol correct
4. Radar responds with 0x631 initialization

### What Doesn't Work (Yet)
1. No 0x300 status messages (still in plant mode)
2. Error codes persist despite parameter changes
3. No combination eliminates all errors

### Hypotheses

1. **Stored Configuration Mismatch**
   - Radar has specific config from original vehicle
   - We haven't found the exact combination yet

2. **Missing Message**
   - Some required message not being sent
   - Timing or frequency issue

3. **Security Lock**
   - Radar may require security access before plant exit
   - VIN learn may be required via UDS

4. **Firmware-Level Lock**
   - Plant mode may be flagged in EEPROM
   - May require firmware modification

## Next Steps

### Short Term
1. [ ] Complete UK-focused brute force sweep
2. [ ] Try all European country codes
3. [ ] Investigate UDS security access

### Medium Term
1. [ ] Attempt VIN learn via UDS service 0x31
2. [ ] Read all accessible DIDs to understand stored config
3. [ ] Analyze firmware if available

### Long Term
1. [ ] JTAG extraction of firmware
2. [ ] Reverse engineer plant mode flag location
3. [ ] Develop direct EEPROM modification tool

## Data Files

| File | Contents |
|------|----------|
| `gateway_probe_history.jsonl` | Raw probe results (208+ runs) |
| `gateway_probe_results.json` | Aggregated analysis |
| `radar_run_history.jsonl` | Detailed activation logs |

## Timeline

| Date | Activity | Result |
|------|----------|--------|
| 2025-07 | Initial protocol development | VIN protocol working |
| 2025-08 | Monitoring tools created | 0x631 detection |
| 2025-10 | Systematic parameter sweeps | Error patterns identified |
| 2026-01 | Repository consolidation | Clean structure, UK focus |

## Notes

### UK P90D Specifications (Best Guess)
- Country: 826 (UK)
- RHD: 1 (yes)
- AWD: 1 (P90D is dual motor)
- Air Suspension: 3 (likely installed)
- Performance Config: 2
- EPAS Type: 1 (Bosch L538)
- Chassis Type: 1 (Model S)
- Radar Position: 0 or 1 (pre/post facelift)

### Useful Resources
- `references/tesla_odj/` - ODJ diagnostic definitions
- `references/openpilot/` - Panda safety layer reference
- `dbc/tesla_*.dbc` - CAN signal definitions
