"""Short Authentication String (SAS) derivation from ECDH shared key.

Uses HKDF to extract a 4-word verification string that both parties
can compare verbally to detect MITM attacks on the first connection.
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# 256 common English words — short, unambiguous, easy to read aloud
WORD_LIST = [
    "apple", "arrow", "atlas", "beach", "blade", "bloom", "board", "brick",
    "bridge", "brook", "brush", "cabin", "cable", "cairn", "canal", "cedar",
    "chain", "chalk", "chess", "cliff", "clock", "cloud", "coast", "coral",
    "crane", "creek", "crest", "cross", "crown", "crypt", "curve", "cycle",
    "delta", "depot", "depth", "derby", "diver", "drift", "drone", "drum",
    "dunes", "eagle", "earth", "eight", "ember", "epoch", "erode", "event",
    "fable", "falls", "fence", "ferry", "field", "fjord", "flame", "flash",
    "fleet", "flint", "floss", "flute", "foamy", "forge", "forte", "forum",
    "frost", "frame", "frond", "gable", "giant", "glade", "glass", "gleam",
    "globe", "gloss", "glove", "glint", "glyph", "grace", "grade", "grain",
    "grand", "graph", "grass", "gravel", "green", "grind", "grove", "guide",
    "guild", "guile", "guise", "hatch", "haven", "hazel", "heart", "heron",
    "hinge", "hippo", "hoist", "holly", "honey", "horde", "hover", "inlay",
    "inlet", "ivory", "ionic", "irony", "jaguar", "jasper", "jetty", "jewel",
    "joint", "kayak", "knoll", "kraft", "lance", "laser", "latch", "lemon",
    "level", "light", "linen", "liner", "lodge", "logic", "lotus", "lunar",
    "magma", "maple", "march", "marsh", "match", "mauve", "medal", "merge",
    "metal", "metro", "mitre", "model", "moose", "morse", "mossy", "mount",
    "mulch", "mural", "nerve", "nexus", "niche", "nitre", "noble", "nomad",
    "notch", "novel", "oaken", "ocean", "olive", "onyx", "optic", "orbit",
    "oxide", "ozone", "paint", "panel", "parch", "patch", "pearl", "pedal",
    "pixel", "pivot", "plaid", "plain", "plane", "plank", "plant", "plaza",
    "plumb", "plume", "polar", "porch", "prism", "probe", "prone", "psalm",
    "pulse", "pumice", "quartz", "quench", "quota", "radar", "rails", "raven",
    "reach", "realm", "resin", "ridge", "rivet", "rocky", "rouge", "rover",
    "royal", "rupee", "rusty", "sable", "saddle", "salon", "sands", "scale",
    "scout", "serge", "shale", "shear", "shelf", "shell", "shift", "shine",
    "shore", "sigma", "sinew", "sixth", "skiff", "slate", "sleek", "sleet",
    "slope", "smoke", "snare", "solar", "solid", "sonic", "spark", "spear",
    "spire", "spoke", "spray", "squad", "stamp", "stark", "stave", "steam",
    "steel", "steep", "steer", "stern", "stirp", "stock", "stone", "storm",
    "stout", "stove", "strap", "straw", "stray", "strut", "sunlit", "swamp",
    "sword", "synth", "talon", "targe", "taupe", "tempo", "terra", "thorn",
    "tidal", "timber", "titan", "token", "topaz", "torch", "tower", "toxic",
    "trace", "track", "trail", "train", "trait", "tramp", "trawl", "treed",
    "trend", "triad", "trial", "tribe", "trout", "trove", "truss", "tuned",
    "ultra", "umbra", "unity", "upper", "urban", "valve", "vapor", "vault",
    "visor", "vivid", "vortex", "waltz", "watch", "water", "weave", "wedge",
    "wharf", "wheat", "wheel", "whelp", "whirl", "willow", "winch", "witch",
    "woven", "wraith", "xenon", "yield", "zebra", "zenith", "zonal",
]

def deriveSas(sharedKey, numWords=4):
    """Derive a Short Authentication String from the ECDH shared key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=numWords,
        salt=None,
        info=b"assp-cipher-sas-v1",
    )
    sasBytes = hkdf.derive(sharedKey)
    return [WORD_LIST[b % len(WORD_LIST)] for b in sasBytes]

def formatSas(words):
    """Return the SAS as a display string."""
    return "  ·  ".join(w.upper() for w in words)
