"""Framing utility module for TCP communication.

Provides functions for sending and receiving length-prefixed frames.
"""

import struct

def recvExact(conn, numBytes):
    """Receive exactly numBytes from the socket."""
    data = bytearray()
    while len(data) < numBytes:
        packet = conn.recv(numBytes - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def recvFramed(conn):
    """Receive a length-prefixed frame."""
    lengthBytes = recvExact(conn, 4)
    if not lengthBytes:
        return None
    length = struct.unpack(">I", lengthBytes)[0]
    return recvExact(conn, length)

def sendFramed(conn, data):
    """Send a length-prefixed frame."""
    lengthBytes = struct.pack(">I", len(data))
    conn.sendall(lengthBytes + data)
