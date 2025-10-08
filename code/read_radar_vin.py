#!/usr/bin/env python3
"""Query VIN and key identifiers from the Bosch radar using python-can UDS."""
from __future__ import annotations

import argparse

import can

from uds_can import IsoTpError, SessionType, UdsSession

# Radar UDS addressing (standard 11-bit IDs)
TX_ADDRESS = 0x641
RX_ADDRESS = TX_ADDRESS + 0x10

DIDS_TO_QUERY = {
    0xF190: "VIN",
    0xA022: "Plant Mode",
    0xF014: "Board Part Number",
    0xF015: "Board Serial Number",
    0xF188: "ECU Software Number",
    0xF189: "ECU Software Version",
    0xF18B: "Manufacturing Date",
    0xF18C: "ECU Serial Number",
    0xF195: "Supplier SW Version",
    0x505:  "Active Alignment State",
    0x509:  "Service Drive Alignment Status",
    0xFC01: "Alignment Horizontal Angle",
    0xFC02: "Alignment Vertical Angle",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Read VIN/metadata from the Bosch radar via UDS")
    parser.add_argument("--interface", default="slcan", help="python-can interface (default: slcan)")
    parser.add_argument("--channel", default="/dev/cu.usbmodem2057326E55481", help="CAN channel/port")
    parser.add_argument("--bitrate", type=int, default=500000, help="CAN bitrate")
    parser.add_argument("--timeout", type=float, default=1.0, help="ISO-TP receive timeout (seconds)")
    args = parser.parse_args()

    bus = can.interface.Bus(
        bustype=args.interface,
        channel=args.channel,
        bitrate=args.bitrate,
        receive_own_messages=False,
    )
    session = UdsSession(bus, TX_ADDRESS, RX_ADDRESS, timeout=args.timeout)

    try:
        print("Sending tester present...")
        session.tester_present()
        print("Switching to extended diagnostic session...")
        session.diagnostic_session_control(SessionType.EXTENDED_DIAGNOSTIC)

        for did, label in DIDS_TO_QUERY.items():
            try:
                data = session.read_data_by_identifier(did)
                try:
                    text = data.decode("utf-8").strip("\x00")
                    print(f"{label:<28}: {text} [{data.hex()}]")
                except UnicodeDecodeError:
                    print(f"{label:<28}: {data.hex()}")
            except IsoTpError as e:
                print(f"{label:<28}: ERROR ({e})")

    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()
