__all__ = [
    "create_recon_agent",
    "create_threat_analysis_agent",
    "create_response_agent",
]


def __getattr__(name):
    if name == "create_recon_agent":
        from agents.recon_agent import create_recon_agent
        return create_recon_agent
    if name == "create_threat_analysis_agent":
        from agents.threat_analysis_agent import create_threat_analysis_agent
        return create_threat_analysis_agent
    if name == "create_response_agent":
        from agents.response_agent import create_response_agent
        return create_response_agent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
