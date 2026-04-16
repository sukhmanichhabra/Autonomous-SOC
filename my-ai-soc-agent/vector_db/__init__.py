__all__ = ["ThreatIntelStore"]


def __getattr__(name):
    if name == "ThreatIntelStore":
        from vector_db.threat_intel_store import ThreatIntelStore
        return ThreatIntelStore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
