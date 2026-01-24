# Brute Force Strategy for Plant Mode Exit

## Problem Statement

The radar unit is locked in plant mode and reports error codes indicating parameter mismatches between:
1. Parameters stored in radar EEPROM (from original vehicle)
2. Parameters we're transmitting via gateway emulation (0x398)

Without access to the original vehicle, we cannot read the stored parameters directly. We must find them through systematic testing.

## UK-Focused Approach

This radar was sourced from a UK Model S P90D. The strategy prioritizes UK-specific configurations.

### Priority Country Codes

1. **826 (UK)** - Radar's likely origin, highest priority
2. **276 (Germany)** - Major EU market, common source
3. **250 (France)** - EU market
4. **380 (Italy)** - EU market
5. **724 (Spain)** - EU market
6. **840 (USA)** - If EU codes fail
7. **124 (Canada)** - If US fails
8. **36 (Australia)** - Last resort

### P90D Characteristics

Based on the VIN (5YJSB7E43GF113105) and model:
- **AWD**: Yes (P = Performance, D = Dual motor)
- **Air Suspension**: Likely installed (performance model)
- **Performance Config**: 2 (Performance trim)
- **EPAS Type**: 1 (Bosch L538 for pre-facelift)
- **Chassis Type**: 1 (Model S)
- **Radar Position**: 0 (Pre-facelift) or 1 (Post-facelift)

## Parameter Space

### Critical Parameters (affect error codes)

| Parameter | Range | Values | Notes |
|-----------|-------|--------|-------|
| GTW_country | - | 8 | Priority codes listed above |
| GTW_airSuspensionInstalled | 0-3 | 4 | 0=none, 1-3=variants |
| GTW_epasType | 0-3 | 4 | Steering type |
| GTW_fourWheelDrive | 0-1 | 2 | RWD vs AWD |
| GTW_chassisType | 0-3 | 4 | Model S/X variants |
| GTW_performanceConfig | 0-3 | 4 | Base/Performance |
| radarPosition | 0-2 | 3 | Pre/Post facelift |
| radarEpasType | 0-1 | 2 | EPAS variant |

### Secondary Parameters (less likely to cause errors)

| Parameter | Range | Notes |
|-----------|-------|-------|
| GTW_rhd | 0-1 | UK is RHD (1) |
| GTW_wheelType | 4-12 | 5 values |
| GTW_autopilot | 0-3 | AP1 level |
| GTW_brakeHwType | 0-2 | Brake type |
| GTW_parkSensorGeometryType | 0-2 | Park sensors |

## Search Space

### Full Sweep (per country)
- 4 x 4 x 2 x 4 x 4 x 3 x 2 = **1,536 combinations**
- At 5 seconds per run: ~2 hours per country
- All 8 countries: ~16 hours total

### Quick Scan (most likely combinations)
Focus on P90D UK spec:
- Air suspension: [3, 2, 1] (most likely 3)
- EPAS type: [1, 0, 2] (most likely 1)
- AWD: [1] (P90D is always AWD)
- Chassis: [1, 0] (Model S)
- Performance: [2, 1, 3] (most likely 2)
- Radar position: [0, 1] (pre or post facelift)
- Radar EPAS: [0] (most likely)

Quick scan: ~36 combinations x 8 countries = ~288 runs = ~24 minutes

## Strategy Execution

### Phase 1: Quick Scan
```bash
python scripts/brute_force_gateway.py --quick --country 826
```

### Phase 2: Full UK Sweep
```bash
python scripts/brute_force_gateway.py --country 826
```

### Phase 3: European Sweep (if UK fails)
```bash
python scripts/brute_force_gateway.py --all-countries --stop-on-success
```

### Phase 4: Manual Refinement
If partial success (fewer error codes):
1. Note the best-performing parameters
2. Create a targeted sweep around those values
3. Test adjacent parameter combinations

## Success Criteria

1. **Full Success**: 0x300 messages appear, no error codes in 0x3FF
2. **Partial Success**: Error code count decreases
3. **VIN Accepted**: vin_complete reaches 7/7
4. **Radar Responding**: 0x631 messages appear

## Interpreting Results

### Error Code Analysis

| Pattern | Likely Cause | Action |
|---------|--------------|--------|
| Only COUNTRY_CODE_ERROR (0x02) | Wrong country | Try other countries |
| Only EPAS_TYPE_ERROR (0x20) | Wrong EPAS | Sweep EPAS values |
| Multiple errors | Multiple mismatches | Check all parameters |
| Inconsistent errors | Timing issue | Increase duration |

### Promising Signs

- Error count decreasing: approaching correct config
- Different error codes: making progress
- VIN complete increasing: protocol working
- 0x631 appearing: radar responding

## Data Collection

All runs are logged to:
- `data/probe_results/brute_force_history.jsonl` - Raw results
- `data/probe_results/brute_force_history.json` - Aggregated analysis

Checkpoint saved to:
- `data/brute_force_checkpoint.json` - For resume capability

## Post-Success Steps

Once correct parameters are found:

1. **Document Configuration**
   - Save exact parameter values
   - Note error code progression

2. **Attempt VIN Learn**
   ```bash
   python scripts/activate_radar.py --vin YOUR_VIN [params]
   ```

3. **Verify Permanent Exit**
   - Power cycle radar
   - Check if plant mode persists
   - May need UDS security access for permanent VIN learn

4. **Optional: Read Current EEPROM Values**
   - Use UDS to read DIDs
   - Confirm stored configuration matches
