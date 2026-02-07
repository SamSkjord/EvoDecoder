#!/usr/bin/env python3
"""
PSU Monitor - Monitors SCPI power supply current draw over serial.

Polls the power supply at 0.5s intervals and displays timestamped current
readings with state classification (IDLE / WAKING / ACTIVE). Detects
state transitions and tracks cumulative time spent in each state.

Usage:
    python3 scripts/psu_monitor.py

Press Ctrl+C to stop and see a summary.
"""

import serial
import time
import sys
from datetime import datetime

SERIAL_PORT = "/dev/cu.usbserial-2210"
BAUD_RATE = 115200
POLL_INTERVAL = 0.5
SERIAL_TIMEOUT = 1.0
MAX_RETRIES = 5
RETRY_DELAY = 1.0

# Current thresholds (amps)
IDLE_MAX = 0.30
WAKING_MAX = 0.38


def classify(amps):
    """Classify current draw into a state."""
    if amps < IDLE_MAX:
        return "IDLE"
    elif amps <= WAKING_MAX:
        return "WAKING"
    else:
        return "ACTIVE"


def open_serial():
    """Open the serial port, retrying on failure."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            ser = serial.Serial(
                port=SERIAL_PORT,
                baudrate=BAUD_RATE,
                timeout=SERIAL_TIMEOUT,
            )
            # Drain any stale data
            ser.reset_input_buffer()
            return ser
        except serial.SerialException as e:
            print(f"[!] Serial open failed (attempt {attempt}/{MAX_RETRIES}): {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
    print(f"[!] Could not open {SERIAL_PORT} after {MAX_RETRIES} attempts. Exiting.")
    sys.exit(1)


def query_current(ser):
    """Send MEAS:CURR? and return the measured current in amps, or None on error."""
    try:
        ser.reset_input_buffer()
        ser.write(b"MEAS:CURR?\r\n")
        raw = ser.readline()
        if not raw:
            return None
        text = raw.decode("ascii", errors="replace").strip()
        return float(text)
    except (serial.SerialException, serial.SerialTimeoutException):
        return None
    except (ValueError, UnicodeDecodeError):
        return None


def format_duration(seconds):
    """Format a duration in seconds to a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    if minutes < 60:
        return f"{minutes}m {secs:.1f}s"
    hours = int(minutes // 60)
    mins = minutes % 60
    return f"{hours}h {mins}m {secs:.0f}s"


def main():
    print(f"PSU Monitor - {SERIAL_PORT} @ {BAUD_RATE} baud")
    print(f"Thresholds: IDLE < {IDLE_MAX}A, WAKING {IDLE_MAX}-{WAKING_MAX}A, ACTIVE > {WAKING_MAX}A")
    print(f"Polling every {POLL_INTERVAL}s  |  Ctrl+C to stop")
    print("-" * 60)

    ser = open_serial()
    print(f"[*] Connected to {SERIAL_PORT}")
    print()

    state_time = {"IDLE": 0.0, "WAKING": 0.0, "ACTIVE": 0.0}
    prev_state = None
    state_entered_at = None
    start_time = time.time()
    consecutive_errors = 0

    try:
        while True:
            loop_start = time.time()
            amps = query_current(ser)

            if amps is None:
                consecutive_errors += 1
                now_str = datetime.now().strftime("%H:%M:%S")
                print(f"{now_str} ---.-A  [read error, retrying...]")
                if consecutive_errors >= MAX_RETRIES:
                    print(f"[!] {consecutive_errors} consecutive errors, reconnecting...")
                    ser.close()
                    time.sleep(RETRY_DELAY)
                    ser = open_serial()
                    consecutive_errors = 0
                elapsed = time.time() - loop_start
                time.sleep(max(0, POLL_INTERVAL - elapsed))
                continue

            consecutive_errors = 0
            now = time.time()
            now_str = datetime.now().strftime("%H:%M:%S")
            state = classify(amps)

            # Build the output line
            transition_msg = ""
            if prev_state is not None and state != prev_state:
                # Accumulate time for the previous state
                if state_entered_at is not None:
                    duration = now - state_entered_at
                    state_time[prev_state] += duration

                # Detect meaningful transitions
                if prev_state == "IDLE" and state in ("WAKING", "ACTIVE"):
                    transition_msg = " *** WOKE UP ***"
                elif prev_state == "WAKING" and state == "ACTIVE":
                    transition_msg = " *** WOKE UP ***"
                elif prev_state in ("ACTIVE", "WAKING") and state == "IDLE":
                    if state_entered_at is not None:
                        transition_msg = f" *** SLEPT after {format_duration(duration)} ***"
                    else:
                        transition_msg = " *** SLEPT ***"
                elif prev_state == "ACTIVE" and state == "WAKING":
                    if state_entered_at is not None:
                        transition_msg = f" *** WINDING DOWN after {format_duration(duration)} ***"

                state_entered_at = now
            elif prev_state is None:
                state_entered_at = now

            line = f"{now_str} {amps:.3f}A {state:7s}{transition_msg}"
            print(line)

            prev_state = state
            elapsed = time.time() - loop_start
            time.sleep(max(0, POLL_INTERVAL - elapsed))

    except KeyboardInterrupt:
        # Accumulate final state time
        if prev_state is not None and state_entered_at is not None:
            state_time[prev_state] += time.time() - state_entered_at

        total_time = time.time() - start_time
        print()
        print()
        print("=" * 60)
        print("  SESSION SUMMARY")
        print("=" * 60)
        print(f"  Total monitoring time: {format_duration(total_time)}")
        print()
        for s in ("IDLE", "WAKING", "ACTIVE"):
            t = state_time[s]
            pct = (t / total_time * 100) if total_time > 0 else 0
            bar = "#" * int(pct / 2)
            print(f"  {s:7s}  {format_duration(t):>10s}  ({pct:5.1f}%)  {bar}")
        print("=" * 60)
    finally:
        ser.close()
        print("[*] Serial port closed.")


if __name__ == "__main__":
    main()
