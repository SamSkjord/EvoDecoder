"""Minimal ISO-TP/UDS helpers for the Tesla radar over python-can."""
from __future__ import annotations

import struct
import time
from enum import IntEnum
from typing import Optional

import can


class ServiceType(IntEnum):
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    SECURITY_ACCESS = 0x27
    TESTER_PRESENT = 0x3E
    READ_DATA_BY_IDENTIFIER = 0x22
    READ_MEMORY_BY_ADDRESS = 0x23
    ROUTINE_CONTROL = 0x31
    REQUEST_DOWNLOAD = 0x34
    TRANSFER_DATA = 0x36
    REQUEST_TRANSFER_EXIT = 0x37


class SessionType(IntEnum):
    DEFAULT = 1
    PROGRAMMING = 2
    EXTENDED_DIAGNOSTIC = 3


class AccessType(IntEnum):
    REQUEST_SEED = 1
    SEND_KEY = 2


class RoutineControlType(IntEnum):
    START = 1
    STOP = 2
    REQUEST_RESULTS = 3


class ResetType(IntEnum):
    HARD = 1
    KEY_OFF_ON = 2
    SOFT = 3


NEGATIVE_RESPONSE = {
    0x10: "general reject",
    0x11: "service not supported",
    0x12: "sub-function not supported",
    0x13: "incorrect message length or invalid format",
    0x21: "busy repeat request",
    0x22: "conditions not correct",
    0x24: "request sequence error",
    0x31: "request out of range",
    0x33: "security access denied",
    0x35: "invalid key",
    0x36: "exceeded number of attempts",
    0x37: "required time delay not expired",
    0x78: "response pending",
    0x7E: "sub-function not supported in active session",
    0x7F: "service not supported in active session",
}


class IsoTpError(Exception):
    """Raised for ISO-TP or UDS level failures."""


class IsoTpSession:
    """Tiny ISO-TP implementation using python-can."""

    def __init__(
        self,
        bus: can.BusABC,
        tx_id: int,
        rx_id: int,
        timeout: float = 1.0,
    ) -> None:
        self.bus = bus
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.timeout = timeout

    # --- framing helpers -------------------------------------------------

    def send(self, payload: bytes) -> None:
        if len(payload) <= 7:
            frame = bytes([len(payload)]) + payload
            self._send_frame(frame.ljust(8, b"\x00"))
            return

        size = len(payload)
        first = bytes([(0x10 | ((size >> 8) & 0x0F)), size & 0xFF]) + payload[:6]
        self._send_frame(first.ljust(8, b"\x00"))

        offset = 6
        seq = 0
        fc = self._recv_frame()
        if fc[0] >> 4 != 0x3:
            raise IsoTpError(f"expected flow control frame, got {fc.hex()}")
        block_size = fc[1]
        separation = fc[2] / 1000.0

        while offset < size:
            seq = (seq + 1) & 0xF
            chunk = payload[offset : offset + 7]
            frame = bytes([0x20 | seq]) + chunk
            self._send_frame(frame.ljust(8, b"\x00"))
            offset += len(chunk)
            if separation:
                time.sleep(separation)
            if block_size and (seq % block_size == 0):
                fc = self._recv_frame()
                if fc[0] >> 4 != 0x3:
                    raise IsoTpError(f"expected flow control frame, got {fc.hex()}")

    def recv(self) -> bytes:
        frame = self._recv_frame()
        frame_type = frame[0] >> 4
        if frame_type == 0x0:
            length = frame[0] & 0x0F
            return frame[1 : 1 + length]
        if frame_type != 0x1:
            raise IsoTpError(f"unexpected frame type {frame_type}")

        length = ((frame[0] & 0x0F) << 8) | frame[1]
        payload = bytearray(frame[2:])

        fc = bytes([0x30, 0x00, 0x00])
        self._send_frame(fc.ljust(8, b"\x00"))
        expected_seq = 0
        while len(payload) < length:
            frame = self._recv_frame()
            if frame[0] >> 4 != 0x2:
                raise IsoTpError(f"unexpected consecutive frame {frame.hex()}")
            expected_seq = (expected_seq + 1) & 0xF
            if (frame[0] & 0x0F) != expected_seq:
                raise IsoTpError("consecutive frame sequence error")
            payload.extend(frame[1:])
        return bytes(payload[:length])

    def _send_frame(self, data: bytes) -> None:
        msg = can.Message(arbitration_id=self.tx_id, data=data, is_extended_id=False)
        self.bus.send(msg)

    def _recv_frame(self) -> bytes:
        deadline = time.monotonic() + self.timeout
        while True:
            timeout = max(0.0, deadline - time.monotonic())
            msg = self.bus.recv(timeout)
            if msg and msg.arbitration_id == self.rx_id and msg.dlc:
                return bytes(msg.data)
            if timeout == 0.0:
                raise IsoTpError("timeout waiting for ISO-TP frame")


class UdsSession:
    def __init__(
        self,
        bus: can.BusABC,
        tx_id: int,
        rx_id: Optional[int] = None,
        timeout: float = 1.0,
    ) -> None:
        self.session = IsoTpSession(bus, tx_id, rx_id or (tx_id + 0x10), timeout=timeout)

    # --- UDS primitives --------------------------------------------------

    def uds_request(self, service: ServiceType, subfunction: Optional[int] = None, data: bytes = b"") -> bytes:
        payload = bytes([service])
        if subfunction is not None:
            payload += bytes([subfunction])
        if data:
            payload += data
        self.session.send(payload)

        while True:
            resp = self.session.recv()
            if resp and resp[0] == 0x7F:
                error = resp[2] if len(resp) > 2 else None
                if error == 0x78:  # response pending
                    time.sleep(0.05)
                    continue
                desc = NEGATIVE_RESPONSE.get(error, "unknown error")
                raise IsoTpError(f"UDS negative response: 0x{error:02X} ({desc})")
            if not resp or resp[0] != service + 0x40:
                raise IsoTpError(f"unexpected UDS response: {resp.hex() if resp else 'None'}")
            return resp[1:]

    # --- Convenience wrappers -------------------------------------------

    def tester_present(self) -> None:
        self.uds_request(ServiceType.TESTER_PRESENT, subfunction=0x00)

    def diagnostic_session_control(self, session_type: SessionType) -> None:
        self.uds_request(ServiceType.DIAGNOSTIC_SESSION_CONTROL, subfunction=session_type)

    def security_access(self, access_type: AccessType, key: Optional[bytes] = None) -> bytes:
        request_seed = access_type.value % 2 == 1
        if request_seed:
            if key is not None:
                raise ValueError("security key not allowed for REQUEST_SEED")
            data = None
        else:
            if key is None:
                raise ValueError("security key required for SEND_KEY")
            data = key
        return self.uds_request(ServiceType.SECURITY_ACCESS, subfunction=access_type, data=data)

    def read_data_by_identifier(self, did: int) -> bytes:
        resp = self.uds_request(ServiceType.READ_DATA_BY_IDENTIFIER, data=struct.pack("!H", did))
        if len(resp) < 2 or struct.unpack("!H", resp[:2])[0] != did:
            raise IsoTpError(f"unexpected DID response for 0x{did:04X}: {resp.hex()}")
        return resp[2:]

    def read_memory_by_address(
        self,
        address: int,
        size: int,
        address_bytes: int = 4,
        size_bytes: int = 1,
    ) -> bytes:
        if not (1 <= address_bytes <= 4 and 1 <= size_bytes <= 4):
            raise ValueError("address_bytes and size_bytes must be 1-4")
        fmt = bytes([((size_bytes & 0xF) << 4) | (address_bytes & 0xF)])
        fmt += struct.pack("!I", address)[4 - address_bytes :]
        fmt += struct.pack("!I", size)[4 - size_bytes :]
        resp = self.uds_request(ServiceType.READ_MEMORY_BY_ADDRESS, data=fmt)
        return resp

    def routine_control(self, control_type: RoutineControlType, routine_id: int, routine_data: bytes = b"") -> bytes:
        data = struct.pack("!H", routine_id) + routine_data
        return self.uds_request(ServiceType.ROUTINE_CONTROL, subfunction=control_type, data=data)

    def request_download(self, address: int, size: int) -> int:
        fmt = bytes([0x44]) + struct.pack("!I", address) + struct.pack("!I", size)
        resp = self.uds_request(ServiceType.REQUEST_DOWNLOAD, data=fmt)
        # upper nibble indicates length of max block size
        num_bytes = resp[0] >> 4
        block = struct.unpack("!I", resp[1 : 1 + num_bytes].rjust(4, b"\x00"))[0]
        return block

    def transfer_data(self, block_counter: int, data: bytes) -> bytes:
        return self.uds_request(ServiceType.TRANSFER_DATA, data=bytes([block_counter]) + data)

    def request_transfer_exit(self) -> None:
        self.uds_request(ServiceType.REQUEST_TRANSFER_EXIT)

    def ecu_reset(self, reset_type: ResetType) -> None:
        self.uds_request(ServiceType.ECU_RESET, subfunction=reset_type)


__all__ = [
    "IsoTpError",
    "IsoTpSession",
    "UdsSession",
    "ServiceType",
    "SessionType",
    "AccessType",
    "RoutineControlType",
    "ResetType",
]
