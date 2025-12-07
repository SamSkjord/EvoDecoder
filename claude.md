Project:
Getting a Bosch MRRevo14F radar from a Tesla working in a standalone capacity using OpenPilot's previous work: 
https://tinkla.us/index.php/Tesla_Bosch_Radar_EON 
https://deepwiki.com/BogGyver/
https://github.com/BogGyver/openpilot/blob/tesla_0.6.6/selfdrive/car/tesla/radar_interface.py
https://github.com/BogGyver/openpilot/tree/tesla_0.6.6/selfdrive/car/tesla/radar_tools


We've managed to extract the VIN (5YJSB7E43GF113105) using tesla_radar_reader2.py
/resources/openpilot-tesla_unity_dev/selfdrive/car/modules/radarFlasher contains some of the openpilot code for interacting with the radar, we adapted this to get tesla_radar_reader2.py functioning

We now need to reverse engineer how Tinkla/OpenPilot get's the radar in to an active AND tracking state, we can use the data the Panda device would send (safety_tesla.h) to emulate a real tesla vehicle and get the radar into a fully active state


https://github.com/BogGyver/openpilot/blob/tesla_unity_dev/selfdrive/car/tesla/radar_interface.py
https://github.com/BogGyver/openpilot/blob/tesla_0.6.6/panda/board/safety/safety_teslaradar.h

We have DBC files:
https://github.com/BogGyver/opendbc/blob/tesla_unity_dev/tesla_can.dbc
https://github.com/BogGyver/opendbc/blob/tesla_unity_dev/tesla_can_pre1916.dbc
https://github.com/BogGyver/opendbc/blob/tesla_unity_dev/tesla_radar.dbc

Linked files are all in /resources/
/Users/sam/git/EvoDecoder/resources/openpilot-tesla_unity_dev/selfdrive/car/tesla
/Users/sam/git/EvoDecoder/resources/openpilot-tesla_0.6.6/selfdrive/car/tesla

The Tinkla implementation communicates over CAN2 of the radar however there is some traffic on CAN1 also, we have both connected to our PI via a WaveShare dual can hat (socketcan)
Pi CAN0 = Radar Can1
Pi CAN1 = Radar Can2

The radar requires seeing certain messages on the canbus to activate, we've found a lot of those from the above code but we're still missing the key ingredient to get it actively scanning and returning live data
radar_diagnostic.py get's us 'activated' but not working, the power draw of the radar increases and the power state changes but the 'scan index' doesn't update

============================================================
📊 DIAGNOSTIC ANALYSIS
============================================================

🔍 MESSAGE FREQUENCY ANALYSIS:
   0x300:  16.3 Hz, 4893 changes 📈 DYNAMIC
   0x371:  16.3 Hz, 4892 changes 📈 DYNAMIC
   0x3FF:  16.3 Hz, 4885 changes 📈 DYNAMIC
   0x36A:  16.2 Hz, 4812 changes 📈 DYNAMIC
   0x36B:  16.2 Hz, 4808 changes 📈 DYNAMIC
   0x36D:  16.2 Hz, 4808 changes 📈 DYNAMIC
   0x368:  16.2 Hz, 4806 changes 📈 DYNAMIC
   0x37D:  16.2 Hz, 4806 changes 📈 DYNAMIC
   0x367:  16.2 Hz, 4804 changes 📈 DYNAMIC
   0x36E:  16.2 Hz, 4804 changes 📈 DYNAMIC
   0x365:  16.2 Hz, 4802 changes 📈 DYNAMIC
   0x375:  16.2 Hz, 4802 changes 📈 DYNAMIC
   0x37E:  16.2 Hz, 4802 changes 📈 DYNAMIC
   0x374:  16.2 Hz, 4800 changes 📈 DYNAMIC
   0x37F:  16.2 Hz, 3343 changes 📈 DYNAMIC
   0x377:  16.1 Hz, 4798 changes 📈 DYNAMIC
   0x37B:  16.1 Hz, 4798 changes 📈 DYNAMIC
   0x335:  16.1 Hz, 4794 changes 📈 DYNAMIC
   0x364:  16.1 Hz, 4794 changes 📈 DYNAMIC
   0x378:  16.1 Hz, 4794 changes 📈 DYNAMIC

🔍 SCAN INDEX ANALYSIS:
   Range: 40 - 40
   Unique values: 1
   Most common: 40
   ❌ STATIC SCAN INDEX - Major issue!

🔍 POWER LEVEL ANALYSIS:
   Range: 2 - 2
   Unique values: 1
   Average: 2.0

🔍 ERROR PATTERN ANALYSIS:
   Unique error codes: 15
   Error codes: [24, 32, 56, 64, 88, 96, 120, 128, 152, 160, 184, 192, 216, 224, 248]
   ⚠️  MANY ERROR CODES - Configuration issue likely

🎯 CRITICAL MISSING PIECES:
   1. Static scan index - radar not actively scanning
   2. No 0x631 initialization - radar may need hardware trigger
   3. Excessive error codes - configuration mismatch




You can connect to the pi via SSH in the terminal
```shell
expect -c "
spawn scp example.py pi@192.168.199.200:~/
expect \"password:\"
send \"HOG2hicq7lv5\r\"
expect eof
"
```

```shell
expect -c "
spawn ssh pi@192.168.199.200 \"cd ~/evo && python3 tesla_complete_emulator.py\"
expect \"password:\"
send \"HOG2hicq7lv5\r\"
interact
"
```
