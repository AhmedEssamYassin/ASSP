"""Payload Formatter module for wrapping binary data with a JSON metadata header.

This ensures the stream cipher can handle different types of data (text, files)
by securely embedding the type and metadata (like filename) before encryption.
"""

import json
import struct

def packPayload(metadataDict, rawBytes):
    """Prepend a length-prefixed JSON metadata header to raw bytes.
    
    Format: [4-byte header length (uint32)] + [JSON string] + [Raw Payload]
    """
    metadataJson = json.dumps(metadataDict).encode("utf-8")
    lengthHeader = struct.pack(">I", len(metadataJson))
    return lengthHeader + metadataJson + rawBytes

def unpackPayload(payloadBytes):
    """Extract metadata header and raw bytes from a packed payload.
    
    Returns:
        tuple: (metadataDict, rawBytes)
    """
    if len(payloadBytes) < 4:
        raise ValueError("Payload too short to contain header length")
        
    headerLen = struct.unpack(">I", payloadBytes[:4])[0]
    
    if len(payloadBytes) < 4 + headerLen:
        raise ValueError("Payload too short to contain full header")
        
    metadataJson = payloadBytes[4:4+headerLen].decode("utf-8")
    metadataDict = json.loads(metadataJson)
    
    rawBytes = payloadBytes[4+headerLen:]
    return metadataDict, rawBytes
