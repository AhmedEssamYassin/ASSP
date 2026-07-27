"""Known-peer fingerprint cache for automatic re-verification within a session.

Since Ed25519 identity keypairs are ephemeral per process, this cache only
persists for the lifetime of the application. It allows repeated connections
from the same peer during a single run to skip the SAS step after the first
successful verification.

Keyed by Ed25519 fingerprint (not host:port) so the cache is stable regardless
of ephemeral TCP source ports or reconnects from different local ports.
"""

_trustedFingerprints = set()

def saveKnownServer(fingerprint):
    """Pin a peer fingerprint after first successful SAS verification."""
    _trustedFingerprints.add(fingerprint)

def isTrusted(fingerprint):
    """Return True if this fingerprint was already verified in this session."""
    return fingerprint in _trustedFingerprints
