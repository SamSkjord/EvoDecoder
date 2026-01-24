# Tesla Radar Protocol Reference

Consolidated protocol documentation for the Bosch MRR evo14 radar module used in Tesla Model S/X vehicles.

## Overview

The radar operates on the vehicle CAN bus at 500 kbps and requires proper gateway (GTW) and vehicle environment emulation to exit plant/factory mode.

## Key Message IDs

### Radar Output Messages

| ID | Name | Rate | Description |
|----|------|------|-------------|
| 0x300 | RadarStatus | 100Hz | Main radar status - appears when radar exits plant mode |
| 0x631 | RadarInit | ~4Hz | Initialization heartbeat during plant mode |
| 0x3FF | SystemStatus | 10Hz | Contains plant mode failure status in byte[1] |

### Required Vehicle Messages (to radar)

| ID | Name | Rate | Description |
|----|------|------|-------------|
| 0x169 | WheelSpeeds | 100Hz | Wheel speed (km/h) for all four wheels |
| 0x199 | VehicleState | 100Hz | Vehicle dynamics state |
| 0x109 | BrakeControl | 100Hz | Brake system state |
| 0x119 | SteeringAngle | 100Hz | Steering wheel angle |
| 0x129 | Acceleration | 50Hz | Vehicle acceleration |
| 0x149 | ESP_Status | 50Hz | ESP/stability control state |
| 0x159 | TractionControl | 50Hz | Traction control state |
| 0x1A9 | ABS_Status | 50Hz | ABS state |
| 0x2A9 | RadarConfig | 1Hz | Radar position and EPAS type |
| 0x2B9 | VIN_Data | 4Hz | VIN transmission (3-part protocol) |
| 0x398 | GatewayConfig | 10Hz | Gateway vehicle configuration |
| 0x508 | VIN_Gateway | 4Hz | VIN from gateway (3-part) |

### Supporting Messages

| ID | Name | Rate | Description |
|----|------|------|-------------|
| 0x101 | EPAS_Control | 100Hz | Electric power steering control |
| 0x214 | EPB_Control | 100Hz | Electronic parking brake control |
| 0x108 | DI_Torque1 | 100Hz | Drive inverter torque |
| 0x118 | DI_Torque2 | 100Hz | Drive inverter torque 2 |
| 0x145 | ESP_145 | 100Hz | ESP longitudinal/lateral accel |
| 0x175 | Unknown | 100Hz | Required but purpose unknown |
| 0x1D8 | Unknown | 100Hz | Required but purpose unknown |
| 0x2C1 | MultiplexedData | 100Hz | Multiplex frame with rolling ID |
| 0x00E | StW_AnglHP | 100Hz | High-precision steering angle |
| 0x045 | StW_Actn | 100Hz | Steering wheel action request |
| 0x17C | DriverStatus | 10Hz | Driver status heartbeat |
| 0x209 | ClimateState | 10Hz | HVAC state |
| 0x219 | SystemConfig | 10Hz | System configuration |
| 0x2D9 | Unknown | 1Hz | Required at 1Hz |

## CRC/Checksum Algorithms

### CRC8 (used on most messages)
```
Polynomial: 0x1D
Initial value: 0xFF
Final XOR: 0xFF
```

### Simple Checksum
```python
checksum = (msg_id & 0xFF) + ((msg_id >> 8) & 0xFF) + sum(data_bytes)
```

## Gateway Configuration (0x398)

The 0x398 message contains critical vehicle configuration that the radar validates against its stored parameters.

### Signal Layout

| Signal | Bits | Description |
|--------|------|-------------|
| GTW_dasHw | 0-1 | DAS hardware type |
| GTW_fourWheelDrive | 2 | AWD flag (0=RWD, 1=AWD) |
| GTW_performanceConfig | 3-4 | Performance config (0-3) |
| GTW_airSuspensionInstalled | 5-6 | Air suspension (0-3) |
| GTW_forwardRadarHw | 7 | Forward radar hardware |
| GTW_parkAssistInstalled | 8-9 | Park assist (0-2) |
| GTW_country | 10-19 | ISO 3166 country code |
| GTW_radarPosition | 20-21 | Radar position (0-2) |
| GTW_bodyControlsType | 22 | Body controls type |
| GTW_rhd | 23 | Right-hand drive (0=LHD, 1=RHD) |
| GTW_parkSensorGeometryType | 24-25 | Park sensor geometry |
| GTW_chassisType | 26-27 | Chassis type (0-3) |
| GTW_epasType | 28-29 | EPAS type (0-3) |
| GTW_frontCornerRadarHw | 30 | Front corner radar |
| GTW_rearCornerRadarHw | 31 | Rear corner radar |
| GTW_wheelType | 40-43 | Wheel type code |
| GTW_autopilot | 44-45 | Autopilot level (0-3) |
| GTW_brakeHwType | 46-47 | Brake hardware type |
| GTW_foldingMirrorsInstalled | 48 | Folding mirrors flag |
| GTW_euVehicle | 49 | EU vehicle flag |

### Country Codes (ISO 3166 numeric)

| Code | Country |
|------|---------|
| 826 | United Kingdom |
| 840 | United States |
| 276 | Germany |
| 250 | France |
| 380 | Italy |
| 724 | Spain |
| 124 | Canada |
| 36 | Australia |

## Radar Configuration (0x2A9)

| Signal | Bits | Description |
|--------|------|-------------|
| radarPosition | 4-5 | 0=Pre-facelift S, 1=Post-facelift S, 2=Model X |
| radarEpasType | 12-13 | 0=Bosch L538, 1=Bosch L405 |
| fourWheelDrive | 3 | AWD flag |

## VIN Protocol (0x2B9)

VIN is transmitted in 3 frames at 4Hz:

| Frame | Byte 0 | Bytes 1-7 |
|-------|--------|-----------|
| 0x10 | 0x10 | VIN[0:3] + padding |
| 0x11 | 0x11 | VIN[3:10] |
| 0x12 | 0x12 | VIN[10:17] |

The radar tracks VIN reception and sets `tesla_radar_vin_complete` to 7 when all 7 cycles complete.

## Plant Mode Failure Codes

See [PLANT_MODE_FAILURE_CODES.md](PLANT_MODE_FAILURE_CODES.md) for the complete list.

The failure code is a bitmask:
- Bit 1 (0x02): COUNTRY_CODE_ERROR
- Bit 2 (0x04): DRIVE_TRAIN_ERROR
- Bit 3 (0x08): VIN_ERROR
- Bit 4 (0x10): AIR_SUSPENSION_ERROR
- Bit 5 (0x20): EPAS_TYPE_ERROR
- Bit 6 (0x40): CHASSIS_TYPE_ERROR

## Timing Requirements

- Radar requires stable message stream for ~3 seconds before responding
- VIN must be transmitted 7 complete cycles before radar accepts it
- Power cycling should have minimum 1.5s off, 3s wait before activation

## Security Access

The radar supports UDS security access (service 0x27) for privileged operations:

- Level 1: Read access
- Level 3: Write access (VIN learn)
- Level 5: Programming mode

Seed-key algorithm is Bosch-specific and documented in `radar_flasher.py`.

## References

- Panda safety layer: `safety_teslaradar.h`
- ODJ diagnostic definitions: `references/tesla_odj/Model S/RADC.odj.json`
- DBC files: `dbc/tesla_*.dbc`
