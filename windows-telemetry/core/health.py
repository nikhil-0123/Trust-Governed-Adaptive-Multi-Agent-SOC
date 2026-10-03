import time
from .agent_identity import AgentIdentity

class HealthMonitor:
    def __init__(self, agent_identity: AgentIdentity, version: str, start_time: float):
        self.agent_identity = agent_identity
        self.version = version
        self.start_time = start_time

    def get_status(self) -> dict:
        uptime = time.time() - self.start_time
        return {
            "status": "healthy",
            "agent_id": self.agent_identity.agent_id,
            "hostname": self.agent_identity.get_hostname(),
            "os": self.agent_identity.get_os(),
            "version": self.version,
            "uptime_seconds": round(uptime, 2)
        }
