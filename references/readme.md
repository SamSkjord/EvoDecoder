# References

- talas9/tesla_can_signals – Model S CAN signal definitions
  <https://github.com/talas9/tesla_can_signals/tree/main/ModelS>
- talas9/tesla_odj – Radar (RADC) ODJ metadata with plant-mode routine decoding
  <https://github.com/talas9/tesla_odj/tree/main/Model%20S>
- Comma.ai OpenPilot Tesla safety layer (v0.6.6 snapshot) – baseline CAN CRC/checksum algorithms
  (copy already present under `resources/openpilot-tesla_0.6.6/`)
- SydneyG Model 3 EPAS/ABS emulators – inspiration for dynamic steering/ABS frames
  <https://github.com/sydneyg007/Tesla-Model-3-EPAS-emulator>
  <https://github.com/sydneyg007/Tesla-Model-3-ABS-Emulator>
- Open Vehicles CAN-RE-Tool – Tesla Model S rules (`ID 0x508` VIN broadcast, country code on `0x398`)
  <https://github.com/openvehicles/CAN-RE-Tool/blob/master/rules/teslamodels>
- Scan My Tesla shared sheet – production signal ranges for drivetrain/battery frames
  <https://docs.google.com/spreadsheets/d/1UBHw2eY3QyJL3vUz0CnTZ7iLlLB-ao5s61hexT0GuHM/edit?gid=0>
- Lunars Tesla dumps – exported configuration CSVs (2016 P90DL, 2014 S85, 2014 P85+)
  <https://github.com/Lunars/tesla>
- Tesware alert catalogue – RCM2_a641_comGTWCarConfigMIA (0x398 GTW_carConfig MIA)
  <https://tesware.net/alerts/model3/RCM2_a641_comGTWCarConfigMIA>
- Model 3 CAN signal spreadsheet (GTW_carConfig fields, EPAS/Air mappings)
  <https://docs.google.com/spreadsheets/d/1ijvNE4lU9Xoruvcg5AhUNLKr7xYyHcxa8YSkTxAERUw/edit?gid=0>
- Josh Wardell Model 3 CAN DBC (Model3CAN.dbc)
  <https://github.com/joshwardell/model3dbc/blob/master/Model3CAN.dbc>
- Tesla Owners Online – Diagnostic port and data access thread (community CAN logging / gateway config notes)
  <https://www.teslaownersonline.com/threads/diagnostic-port-and-data-access.7502/>
- Dennis Noermann car-tools (Bosch MRRevo14 patching & VW ACC CAN utilities)
  <https://github.com/dnoermann/car-tools>
- Comma.ai OpenDBC Tesla radar generator (0x2A9/0x159/0x169 signal names)
  <https://github.com/commaai/opendbc/blob/master/opendbc/dbc/generator/tesla/tesla_radar_bosch.py>
