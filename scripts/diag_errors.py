#!/usr/bin/env python3
"""Quick diagnostic: capture 0x3FF error codes and decode them."""
import sys, time, threading
sys.path.insert(0, ".")

from src.protocol.tesla_radar_protocol import TeslaRadarProtocol, setup_can

# Power cycle
import serial
print("Power cycling...")
with serial.Serial("/dev/cu.usbserial-2210", 115200, timeout=1) as ser:
    ser.write(b"OUTP 0\r\n"); ser.flush(); time.sleep(1.5)
    ser.write(b"OUTP 1\r\n"); ser.flush()
time.sleep(3.0)

bus = setup_can(interface="can0")
proto = TeslaRadarProtocol(bus, debug=False)

collected_3ff = []
scan_indices = set()
status_count = [0]

def diag_monitor():
    while proto.running:
        try:
            msg = proto.can_bus.recv(timeout=0.1)
        except Exception:
            continue
        if msg is None:
            elapsed = time.time() - proto.last_radar_signal
            if elapsed > 1.0 and proto.tesla_radar_status > 0:
                proto.tesla_radar_status = 0
            continue
        mid = msg.arbitration_id
        if mid == 0x631:
            if proto.tesla_radar_status == 0:
                proto.tesla_radar_status = 1
                proto.last_radar_signal = time.time()
            elif proto.tesla_radar_status > 0:
                proto.last_radar_signal = time.time()
            proto.init_message_count += 1
        elif mid == 0x300:
            if proto.tesla_radar_status == 1:
                proto.tesla_radar_status = 2
                proto.last_radar_signal = time.time()
            elif proto.tesla_radar_status == 2:
                proto.last_radar_signal = time.time()
            proto.status_message_count += 1
            if len(msg.data) >= 2:
                scan_indices.add(msg.data[1])
            status_count[0] += 1
        elif mid == 0x3FF:
            collected_3ff.append(bytes(msg.data))

proto.monitor_radar_responses = diag_monitor
t = threading.Thread(target=proto.start, daemon=True)
t.start()
print("Running for 12 seconds...")
time.sleep(12)
proto.stop()
time.sleep(0.5)
bus.shutdown()

# Analyze
print(f"\n{'='*60}")
print(f"0x300 count: {status_count[0]}")
print(f"Scan indices: {len(scan_indices)} unique")
print(f"0x3FF messages: {len(collected_3ff)}")

# Decode error bytes
error_byte1_counts = {}
for raw in collected_3ff:
    if len(raw) >= 2:
        b1 = raw[1]
        if b1 != 0:
            error_byte1_counts[b1] = error_byte1_counts.get(b1, 0) + 1

bits_map = {0x08: "VIN", 0x10: "AIR_SUSP", 0x20: "EPAS", 0x40: "CHASSIS", 0x80: "BIT7"}
all_bits = set()

print(f"\nError codes (byte[1] of 0x3FF):")
for code, count in sorted(error_byte1_counts.items()):
    flags = []
    for bit, name in bits_map.items():
        if code & bit:
            flags.append(name)
            all_bits.add(name)
    flag_str = " | ".join(flags) if flags else "low bits only"
    print(f"  0x{code:02X} ({code:3d}): {count:3d}x  flags: {flag_str}")

print(f"\nAll error flags present: {sorted(all_bits)}")

# Unique raw payloads
print(f"\nUnique 0x3FF payloads:")
seen = set()
for raw in collected_3ff:
    h = raw.hex()
    if h not in seen:
        seen.add(h)
        print(f"  {h}  (byte0=0x{raw[0]:02X} byte1=0x{raw[1]:02X})")
    if len(seen) >= 20:
        break

# Show current config
print(f"\nCurrent 0x398 config sent to radar:")
print(f"  country={proto.gateway_country} awd={proto.force_awd}")
print(f"  air_susp={proto.gateway_air_suspension} epas={proto.gateway_epas_type}")
print(f"  chassis={proto.gateway_chassis_type} perf={proto.gateway_performance_config}")
print(f"  autopilot={proto.gateway_autopilot_level} das_hw={proto.gateway_das_hw}")
print(f"  rhd={proto.gateway_rhd} forward_radar_hw={proto.gateway_forward_radar_hw}")
