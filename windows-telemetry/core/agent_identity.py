import os
import uuid
import platform
import json

class AgentIdentity:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.identity_file = os.path.join(data_dir, "agent_identity.json")
        self.agent_id = self._load_or_generate_identity()

    def _load_or_generate_identity(self) -> str:
        if os.path.exists(self.identity_file):
            try:
                with open(self.identity_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "agent_id" in data:
                        return data["agent_id"]
            except Exception:
                pass # Fallback to generation if file is corrupted
        
        # Generate new persistent unique agent ID
        new_id = str(uuid.uuid4())
        self._save_identity(new_id)
        return new_id

    def _save_identity(self, agent_id: str):
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.identity_file, 'w', encoding='utf-8') as f:
            json.dump({"agent_id": agent_id}, f, indent=4)

    def get_hostname(self) -> str:
        return platform.node()

    def get_os(self) -> str:
        return platform.system()

    def get_platform_info(self) -> str:
        return platform.platform()
