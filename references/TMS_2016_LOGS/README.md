# Tesla Model S CAN logs 
Goal: CAN control of iBooster


## Vehicle Details

VIN: 5YJSA1E18GF1XXXXX

1-3	Manufacturer	5YJ = Tesla, Inc.

4	Make	S = Model S

5	Body Type	A = 5 Door Hatchback LHD (Left-Hand Drive)

6	Restraint System	1 = Manual Type 2 Seat Belts (Front, Rear*3) With Front Airbags, PODS, Side Inflatable Restraints, Knee Airbags (Front)

7	Battery Type	E = Lithium-Ion Battery - Electric

8	Motor/Drive Unit	1 = Single Motor - Three Phase A/C Induction

9	Check Character	8

10	Model Year	G = 2016

11	Location of Manufacture	F = Fremont, CA, USA

### Features
- Summon Mode
- AP1
- Autosteer: worked for one of the drives, then shut off and wouldn't reactivate
- Adaptive Cruise

## Test Setup

### Buses
Bus 0: CAN6 Chassis

Bus 1: CAN3 Powertrain

### Logger
SavvyCAN v199 - Mac OS Catalina

EVTV ESP32_CAN

## Logs
### Summon Mode:
Parked car in front of wall

- short: ~2m, car stopped at wall
- long: ~10m, car stopped at wall
- max ~30m, car stopped before reaching wall

- fwd: Summoned car forward
- bck: Summoned car backward
- return: returned to initial position

- car: started from inside car, pressing parking button twice, then selecting direction
- fob: held center button until hazards flashed, then pressed frunk button for forward direction or trunk button for reverse direction

- warnings: car threw a bunch of warnings and shut off
- aborted: manually stopped the car by interrupting summon mode with fob button press

summon6_bck_long_car.csv : Run 6, summoned car backward from ~10m, initiated command from inside car UI
summon6_return_long_fob.csv : Run 6, returned car to original position, initiated command from fob



### Driving:
Ran continuous logging while car was driving with cruise control on

- stopandgo: drove with cruise control (on and off) along a long street with lots of stop signs, traffic lights, verified regen and iBooster braking was working
- highways: drove with cruise control (continuously) along a highway


- clean: started logging, shut off car, walked away, entered car, started, drove, parked, shut off car, walked away, stopped logging
- dirty: either started logging while car was on, or stopped before car was off
- neither clean nor dirty: entered car, started logging, turned on car, drove, parked, stopped logging
- warnings: car threw a bunch of warnings and shut off

