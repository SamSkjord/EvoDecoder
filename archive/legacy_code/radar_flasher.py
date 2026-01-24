#!/usr/bin/env python3
"""Python-can port of the radar VIN/parameter utilities from radarFlasher."""
from __future__ import annotations

import argparse
import binascii
import hashlib
import struct
import threading
import time
from binascii import hexlify
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover - optional dependency
    def tqdm(iterable, **_):
        return iterable

import can

from uds_can import (
    IsoTpError,
    ResetType,
    RoutineControlType,
    ServiceType,
    SessionType,
    UdsSession,
)

try:
    from tesla_radar_activator import TeslaRadarProtocol
except ImportError:  # pragma: no cover
    TeslaRadarProtocol = None


def _encode_country(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    value = value.strip()
    if value.startswith("0x"):
        return int(value, 16)
    if value.isdigit():
        return int(value)
    if len(value) == 2:
        return (ord(value[0]) << 8) | ord(value[1])
    raise ValueError(
        "GTW_country must be provided as integer, hex string, or two-character ASCII"
    )

# Monkey-patch python-can slcan interface to tolerate malformed ASCII frames produced by
# concurrent protocol traffic. This ensures UDS sessions continue instead of raising ValueError.
for _path in ("can.interfaces.slcan", "can.interfaces.slcan.bus"):
    try:  # pragma: no cover
        module = __import__(_path, fromlist=["SlcanBus"])
        SlcanBus = getattr(module, "SlcanBus")

        _orig_recv_internal = SlcanBus._recv_internal

        def _safe_recv_internal(self, timeout=None):
            while True:
                try:
                    return _orig_recv_internal(self, timeout)
                except ValueError:
                    continue

        SlcanBus._recv_internal = _safe_recv_internal
    except (ImportError, AttributeError):
        continue

TX_ADDRESS = 0x641
RX_ADDRESS = TX_ADDRESS + 0x10

DEFAULT_FW_START = 0x7000
DEFAULT_FW_END = 0x45FFF
DEFAULT_FW_MD5 = "9e51ddd80606fbdaaf604c73c8dde0d1"


class _GatewayLoop:
    def __init__(self, protocol: TeslaRadarProtocol, interval: float = 0.05) -> None:
        self.protocol = protocol
        self.interval = interval
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while self._running:
            try:
                self.protocol.send_398_message()
                self.protocol.send_101_message()
                self.protocol.send_214_message()
            except Exception:
                pass
            time.sleep(self.interval)

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def tesla_radar_security_access_algorithm(seed: bytes) -> int:
    if len(seed) != 4:
        raise ValueError(f"security seed must be 4 bytes, got {len(seed)}")
    seed_val = int.from_bytes(seed, byteorder="big")
    k4 = (seed_val >> 5 & 8) | (seed_val >> 0xB & 4) | (seed_val >> 0x18 & 1) | (seed_val >> 1 & 2)
    if seed_val & 0x20000 == 0:
        k32 = ((seed_val & ~(0xFF << k4 & 0xFFFFFFFF)) << (0x20 - k4) & 0xFFFFFFFF) | (seed_val >> k4 & 0xFFFFFFFF)
    else:
        k32 = ((~(0xFF << k4 & 0xFFFFFFFF) << (0x20 - k4) & seed_val & 0xFFFFFFFF) >> (0x20 - k4) & 0xFFFFFFFF) | (seed_val << k4 & 0xFFFFFFFF)
    k2 = (seed_val >> 4) & 2 | (seed_val >> 0x1F)
    if k2 == 0:
        key_int = k32 | seed_val
    elif k2 == 1:
        key_int = k32 & seed_val
    elif k2 == 2:
        key_int = k32 ^ seed_val
    else:
        key_int = k32
    return key_int & 0xFFFFFFFF


def vin_learn(session: UdsSession, protocol: Optional[TeslaRadarProtocol] = None) -> None:
    gateway: Optional[_GatewayLoop] = None
    try:
        if protocol is not None:
            if TeslaRadarProtocol is None:
                raise RuntimeError("TeslaRadarProtocol not available")
            print("[VIN LEARN] Starting gateway emulation thread...")
            gateway = _GatewayLoop(protocol)
            gateway.start()

        print("[VIN LEARN] Starting diagnostic session")
        session.tester_present()
        session.diagnostic_session_control(SessionType.DEFAULT)
        session.diagnostic_session_control(SessionType.EXTENDED_DIAGNOSTIC)

        print("Requesting seed (level 0x11)...")
        seed_response = session.uds_request(ServiceType.SECURITY_ACCESS, subfunction=0x11)
        if not seed_response:
            raise IsoTpError("empty seed response")
        seed_level = seed_response[0]
        seed = seed_response[1:]
        print(f"  seed level: 0x{seed_level:02X} seed: {seed.hex()}")
        key = struct.pack("!I", tesla_radar_security_access_algorithm(seed))
        print(f"Sending key (0x12): {key.hex()}")
        session.uds_request(ServiceType.SECURITY_ACCESS, subfunction=0x12, data=key)

        print("Triggering VIN learn routine (0x0A03 / 2563)...")
        session.routine_control(RoutineControlType.START, 0x0A03)

        # Stop routine and request results
        attempts = 0
        max_attempts = 10
        while attempts < max_attempts:
            time.sleep(2)
            try:
                session.routine_control(RoutineControlType.STOP, 0x0A03)
                break
            except IsoTpError as err:
                attempts += 1
                print(f"  stop attempt {attempts} failed: {err}")
        else:
            print("  stop routine did not acknowledge after multiple attempts; requesting results anyway")
        print("Requesting VIN learn results...")
        result = session.routine_control(RoutineControlType.REQUEST_RESULTS, 0x0A03)
        print(f"VIN learn complete [{result.hex()}]")

    finally:
        if gateway is not None:
            print("Stopping gateway emulation...")
            gateway.stop()
        if protocol is not None:
            protocol.stop()


def read_values(session: UdsSession) -> None:
    print("[EXTRACT PARAMS] Switching diagnostic session")
    session.diagnostic_session_control(SessionType.DEFAULT)
    session.diagnostic_session_control(SessionType.EXTENDED_DIAGNOSTIC)

    def show(did: int, label: str) -> None:
        try:
            data = session.read_data_by_identifier(did)
            try:
                text = data.decode("utf-8").strip("\x00")
            except UnicodeDecodeError:
                text = data.hex()
            print(f"{label:<32}: {text} [{hexlify(data).decode()}]")
        except IsoTpError as err:
            print(f"{label:<32}: ERROR ({err})")

    show(0xF190, "VIN")
    show(0xA022, "Plant Mode")
    show(0xF014, "Board Part #")
    show(0xF015, "Board Serial")
    show(0xFC01, "Alignment Horizontal Angle")
    show(0x508, "Alignment Horizontal Screw")
    show(0x505, "Alignment State")
    show(0xFC02, "Alignment Vertical Angle")
    show(0x507, "Alignment Vertical Screw")
    show(0x506, "Alignment Operation")
    show(0x50A, "Service Drive Alignment State")
    show(0x509, "Service Drive Alignment Status")


def main() -> None:
    parser = argparse.ArgumentParser(description="Radar flasher/diagnostic tools (python-can port)")
    parser.add_argument("--interface", default="slcan", help="python-can interface (default: slcan)")
    parser.add_argument("--channel", default="/dev/cu.usbmodem2057326E55481", help="CAN channel/port")
    parser.add_argument("--bitrate", type=int, default=500000, help="CAN bitrate")
    parser.add_argument("--timeout", type=float, default=3.0, help="ISO-TP timeout (seconds)")
    parser.add_argument("--vin", default="5YJSB7E43GF113105", help="VIN for optional gateway emulation")
    parser.add_argument("--debug", action="store_true", help="Enable verbose protocol logging")
    parser.add_argument("--vin-learn", action="store_true", help="Run VIN learn routine")
    parser.add_argument("--extract-params", action="store_true", help="Read VIN/alignment parameters")
    parser.add_argument("--extract-firmware", metavar="OUT", help="Dump firmware to file")
    parser.add_argument("--flash-firmware", metavar="FILE", help="Flash firmware from file")
    parser.add_argument("--fw-start", type=lambda x: int(x, 0), default=DEFAULT_FW_START, help="Firmware start address")
    parser.add_argument("--fw-end", type=lambda x: int(x, 0), default=DEFAULT_FW_END, help="Firmware end address")
    parser.add_argument("--fw-md5", default=DEFAULT_FW_MD5, help="Expected MD5 for stock firmware")
    parser.add_argument("--patch", action="store_true", help="Apply firmware patches before flashing")
    parser.add_argument(
        "--use-protocol",
        action="store_true",
        help="Run TeslaRadarProtocol gateway emulation during VIN learn",
    )
    parser.add_argument("--country", help="GTW_country (int/hex/ASCII)")
    parser.add_argument("--air-suspension", type=int, help="GTW_airSuspensionInstalled")
    parser.add_argument("--performance-config", type=int, help="GTW_performanceConfig")
    parser.add_argument("--chassis-type", type=int, help="GTW_chassisType")
    parser.add_argument("--four-wheel-drive", type=int, choices=[0, 1])
    parser.add_argument("--epas-type", type=int, help="GTW_epasType")
    parser.add_argument("--autopilot-level", type=int, help="GTW_autopilot")
    parser.add_argument("--park-assist", type=int, help="GTW_parkAssistInstalled")
    parser.add_argument("--wheel-type", type=int, help="GTW_wheelType")
    parser.add_argument("--brake-hw-type", type=int, help="GTW_brakeHwType")
    parser.add_argument("--folding-mirrors", type=int, help="GTW_foldingMirrorsInstalled")
    parser.add_argument("--park-geometry", type=int, help="GTW_parkSensorGeometryType")
    parser.add_argument("--forward-radar-hw", type=int, help="GTW_forwardRadarHw")
    parser.add_argument("--eu-vehicle", type=int, choices=[0, 1], help="GTW_euVehicle")
    parser.add_argument("--rhd", type=int, choices=[0, 1], help="GTW_rhd")
    parser.add_argument("--country-override", dest="country_override", help=argparse.SUPPRESS)
    parser.add_argument("--radar-position", type=int, help="radarPosition override")
    parser.add_argument("--radar-epas-type", type=int, help="radarEpasType override")
    parser.add_argument("--das-hw", type=int, help="GTW_dasHw value")
    parser.add_argument(
        "--protocol-speed",
        type=int,
        default=30,
        help="Speed (km/h) for optional gateway emulation",
    )
    args = parser.parse_args()

    if not any(
        [
            args.vin_learn,
            args.extract_params,
            args.extract_firmware,
            args.flash_firmware,
        ]
    ):
        parser.error("choose at least one action")

    bus = can.interface.Bus(
        bustype=args.interface,
        channel=args.channel,
        bitrate=args.bitrate,
        receive_own_messages=False,
    )
    session = UdsSession(bus, TX_ADDRESS, RX_ADDRESS, timeout=args.timeout)

    protocol = None
    if args.use_protocol:
        if TeslaRadarProtocol is None:
            raise RuntimeError("TeslaRadarProtocol is unavailable; install or run from repo root")
        proto_kwargs = {}
        if args.performance_config is not None:
            proto_kwargs["performance_config"] = args.performance_config
        if args.air_suspension is not None:
            proto_kwargs["air_suspension"] = args.air_suspension
        if args.chassis_type is not None:
            proto_kwargs["chassis_type"] = args.chassis_type
        if args.four_wheel_drive is not None:
            proto_kwargs["four_wheel_drive"] = args.four_wheel_drive
        if args.autopilot_level is not None:
            proto_kwargs["autopilot_level"] = args.autopilot_level

        protocol = TeslaRadarProtocol(
            bus,
            vin=args.vin,
            debug=args.debug,
            **proto_kwargs,
        )

        if args.country is not None:
            protocol.gateway_country = _encode_country(args.country)
        if args.forward_radar_hw is not None:
            protocol.gateway_forward_radar_hw = int(args.forward_radar_hw)
        if args.park_assist is not None:
            protocol.gateway_park_assist = int(args.park_assist)
        if args.wheel_type is not None:
            protocol.gateway_wheel_type = int(args.wheel_type)
        if args.brake_hw_type is not None:
            protocol.gateway_brake_hw_type = int(args.brake_hw_type)
        if args.folding_mirrors is not None:
            protocol.gateway_folding_mirrors = int(args.folding_mirrors)
        if args.park_geometry is not None:
            protocol.gateway_park_sensor_geometry = int(args.park_geometry)
        if args.eu_vehicle is not None:
            protocol.gateway_eu_vehicle = int(args.eu_vehicle)
        if args.rhd is not None:
            protocol.gateway_rhd = int(args.rhd)
        if args.das_hw is not None:
            protocol.gateway_das_hw = int(args.das_hw)
        if args.four_wheel_drive is not None:
            protocol.force_awd = bool(args.four_wheel_drive)
        if args.epas_type is not None:
            protocol.gateway_epas_type = int(args.epas_type)
        if args.radar_position is not None:
            protocol.radarPosition = int(args.radar_position)
        if args.radar_epas_type is not None:
            protocol.radarEpasType = int(args.radar_epas_type)

        # Synchronize speed with diagnostic session usage
        protocol.actual_speed_kph = args.protocol_speed
        protocol.base_speed_kph = args.protocol_speed

    try:
        if args.extract_params:
            read_values(session)
        if args.vin_learn:
            vin_learn(session, protocol if args.use_protocol else None)
        if args.extract_firmware:
            out_path = Path(args.extract_firmware)
            extract_firmware(session, args.fw_start, args.fw_end, out_path)
        if args.flash_firmware:
            fw_path = Path(args.flash_firmware)
            firmware = fw_path.read_bytes()
            if args.patch:
                firmware = patch_firmware(firmware, args.fw_start)
                firmware = update_checksums(firmware, args.fw_start)
            flash_firmware(
                session,
                args.fw_start,
                args.fw_end,
                firmware,
                verify_md5=args.fw_md5 if not args.patch else None,
            )
    finally:
        if protocol is not None:
            protocol.stop()
        bus.shutdown()


def _ensure_extended_session(session: UdsSession) -> None:
    session.diagnostic_session_control(SessionType.DEFAULT)
    session.diagnostic_session_control(SessionType.EXTENDED_DIAGNOSTIC)


def extract_firmware(
    session: UdsSession,
    start_addr: int,
    end_addr: int,
    out_file: Path,
    chunk_size: int = 128,
) -> None:
    print("[FW EXTRACT] Switching to extended diagnostic session")
    _ensure_extended_session(session)
    session.tester_present()
    print("Requesting security seed ...")
    seed_response = session.uds_request(ServiceType.SECURITY_ACCESS, subfunction=0x11)
    if not seed_response:
        raise IsoTpError("empty seed response")
    seed_level = seed_response[0]
    seed = seed_response[1:]
    key = struct.pack("!I", tesla_radar_security_access_algorithm(seed))
    print(f"  seed level: 0x{seed_level:02X} seed: {seed.hex()}  key: {key.hex()}")
    session.uds_request(ServiceType.SECURITY_ACCESS, subfunction=0x12, data=key)

    print(f"Reading firmware {hex(start_addr)} - {hex(end_addr)}")
    data = bytearray()
    for addr in tqdm(range(start_addr, end_addr + 1, chunk_size)):
        size = min(chunk_size, end_addr - addr + 1)
        chunk = session.read_memory_by_address(addr, size)
        if len(chunk) != size:
            raise IsoTpError(f"expected {size} bytes at {hex(addr)}, got {len(chunk)}")
        data.extend(chunk)

    out_file.write_bytes(data)
    print(f"Firmware saved to {out_file} ({len(data)} bytes)")
    print(f"MD5: {hashlib.md5(data).hexdigest()}")


def update_checksums(data: bytes, offset: int, restore: bool = False) -> bytes:
    fw = bytearray(data)
    for addr in (0x79C0, 0x79D0):
        idx = addr - offset
        start = struct.unpack("<I", fw[idx:idx + 4])[0]
        end = struct.unpack("<I", fw[idx + 4:idx + 8])[0]
        crc32 = struct.pack("<I", binascii.crc32(fw[start - offset:end - offset + 1]))
        if restore:
            fw[idx + 8:idx + 12] = data[idx + 8:idx + 12]
        else:
            fw[idx + 8:idx + 12] = crc32
    return bytes(fw)


def patch_firmware(data: bytes, offset: int, restore: bool = False) -> bytes:
    fw = bytearray(data)
    mods = [
        (0x031750, b"\x80\xff\x74\x2b", b"\x20\x56\x01\x00"),
        (0x031892, b"\x80\xff\x32\x2a", b"\x20\x56\x01\x00"),
        (0x031974, b"\x80\xff\x50\x29", b"\x20\x56\x01\x00"),
    ]
    for addr, old_val, new_val in mods:
        idx = addr - offset
        original = old_val if not restore else new_val
        replacement = new_val if not restore else old_val
        if fw[idx:idx + len(original)] != original:
            continue
        fw[idx:idx + len(original)] = replacement
    return bytes(fw)


def request_download(session: UdsSession, start_addr: int, data: bytes) -> int:
    fmt = bytes([0x44]) + struct.pack("!I", start_addr) + struct.pack("!I", len(data))
    resp = session.uds_request(ServiceType.REQUEST_DOWNLOAD, data=fmt)
    size_len = resp[0] >> 4
    return struct.unpack("!I", resp[1:1 + size_len].rjust(4, b"\x00"))[0]


def transfer_firmware(session: UdsSession, start_addr: int, data: bytes) -> None:
    block_size = request_download(session, start_addr, data)
    chunk_size = max(1, block_size - 2)
    block_counter = 0
    for offset in tqdm(range(0, len(data), chunk_size)):
        block_counter = (block_counter + 1) & 0xFF
        chunk = data[offset:offset + chunk_size]
        session.transfer_data(block_counter or 1, chunk)
    session.request_transfer_exit()


def flash_firmware(
    session: UdsSession,
    start_addr: int,
    end_addr: int,
    data: bytes,
    verify_md5: Optional[str] = None,
) -> None:
    length = end_addr - start_addr + 1
    if len(data) != length:
        raise ValueError(f"firmware length mismatch: expected {length}, got {len(data)}")
    if verify_md5 and hashlib.md5(data).hexdigest() != verify_md5:
        raise ValueError("firmware MD5 mismatch")

    print("[FW FLASH] Programming session")
    session.diagnostic_session_control(SessionType.PROGRAMMING)
    print("Requesting security seed ...")
    seed_response = session.uds_request(ServiceType.SECURITY_ACCESS, subfunction=0x11)
    if not seed_response:
        raise IsoTpError("empty seed response")
    seed_level = seed_response[0]
    seed = seed_response[1:]
    key = struct.pack("!I", tesla_radar_security_access_algorithm(seed))
    print(f"  seed level: 0x{seed_level:02X} seed: {seed.hex()}  key: {key.hex()}")
    session.uds_request(ServiceType.SECURITY_ACCESS, subfunction=0x12, data=key)

    print("Erasing memory ...")
    start_len = struct.pack(
        ">II", start_addr, length
    )
    session.routine_control(RoutineControlType.START, 0xDC03, start_len)

    print("Transferring new firmware ...")
    transfer_firmware(session, start_addr, data)

    print("Resetting ECU ...")
    try:
        session.ecu_reset(ResetType.HARD)
    except IsoTpError:
        pass
    time.sleep(2)
    _ensure_extended_session(session)
    print("Firmware flash complete")


if __name__ == "__main__":
    main()
