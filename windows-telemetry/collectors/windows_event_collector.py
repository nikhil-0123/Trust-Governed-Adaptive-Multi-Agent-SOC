import os
import subprocess
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Any
from config.settings import config
from .checkpoint import CheckpointManager

class WindowsEventCollector:
    """
    Collects raw Windows events incrementally using native wevtutil.
    Supports live wevtutil queries or simulation event queue files.
    Does NOT normalize or analyze events.
    """
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.log_name = config.windows_security_log_name
        self.batch_size = config.windows_event_batch_size
        self.checkpoint_manager = CheckpointManager(config.checkpoint_dir, self.log_name, logger)
        self.current_checkpoint = 0
        self._warned_permission = False
        self.simulated_events_dir = os.path.join(config.data_dir, "simulated_events")
        
    def initialize(self):
        self.logger.info(f"Initializing WindowsEventCollector for log: {self.log_name}")
        os.makedirs(self.simulated_events_dir, exist_ok=True)
        self.current_checkpoint = self.checkpoint_manager.load_checkpoint()
        if self.current_checkpoint == 0:
            self.logger.info("No checkpoint found. Applying conservative first-run behavior.")
            self._apply_first_run_behavior()
        else:
            self.logger.info(f"Loaded checkpoint: {self.current_checkpoint}")

    def _apply_first_run_behavior(self):
        """
        Conservative default: do not ingest historical data. 
        Fetch the single latest EventRecordID to establish the initial checkpoint.
        """
        cmd = ["wevtutil", "qe", self.log_name, "/c:1", "/rd:true", "/f:xml"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
            if result.stdout.strip():
                events = self._parse_wevtutil_xml(result.stdout)
                if events and "record_id" in events[0]:
                    latest_id = events[0]["record_id"]
                    self.current_checkpoint = latest_id
                    self.checkpoint_manager.save_checkpoint(self.current_checkpoint)
                    self.logger.info(f"First-run checkpoint set to latest event ID: {self.current_checkpoint}")
                    return
        except subprocess.CalledProcessError as e:
            self.logger.warning(
                f"Permission notice: wevtutil query on '{self.log_name}' returned exit code {e.returncode}. "
                "Administrator privileges required for live Windows Security log. "
                "Agent ready for elevated collection or simulated event injection."
            )
            self.current_checkpoint = 1
            self.checkpoint_manager.save_checkpoint(self.current_checkpoint)
            return
        except Exception as e:
            self.logger.error(f"Failed to determine first-run checkpoint: {e}")
            raise RuntimeError(f"First-run checkpoint failure: {e}")

    def _collect_simulated_events(self) -> List[Dict[str, Any]]:
        """Collects simulated event XML files placed in simulated_events_dir."""
        if not os.path.isdir(self.simulated_events_dir):
            return []
        events = []
        try:
            files = sorted([f for f in os.listdir(self.simulated_events_dir) if f.endswith(".xml")])
            for filename in files[:self.batch_size]:
                filepath = os.path.join(self.simulated_events_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                    parsed = self._parse_wevtutil_xml(content)
                    events.extend(parsed)
                    os.remove(filepath)
                except Exception as e:
                    self.logger.error(f"Error reading simulated event file {filepath}: {e}")
        except Exception as e:
            self.logger.error(f"Error accessing simulated events directory: {e}")
        return events

    def collect_once(self) -> List[Dict[str, Any]]:
        """
        Performs a single batch retrieval of events newer than the checkpoint.
        Checks simulated event queue first, then queries live wevtutil.
        """
        # 1. Check for simulated events
        sim_events = self._collect_simulated_events()
        if sim_events:
            self.logger.info(f"Retrieved {len(sim_events)} event(s) from simulation queue.")
            return sim_events

        # 2. Query live wevtutil
        if self.current_checkpoint == 0:
            query = "*[System[(EventRecordID > 0)]]"
        else:
            query = f"*[System[(EventRecordID > {self.current_checkpoint})]]"

        cmd = ["wevtutil", "qe", self.log_name, f"/q:{query}", f"/c:{self.batch_size}", "/f:xml"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        except subprocess.CalledProcessError as e:
            if not self._warned_permission:
                self.logger.warning(
                    f"Live wevtutil query on '{self.log_name}' requires Administrator rights (Exit code {e.returncode}). "
                    "Running in waiting mode. Drop XML files into simulated_events for offline/lab simulation."
                )
                self._warned_permission = True
            return []
        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Timeout querying {self.log_name}: {e}")
            raise RuntimeError(f"wevtutil timeout: {e}")
            
        xml_output = result.stdout.strip()
        if not xml_output:
            return [] # No new events

        events = self._parse_wevtutil_xml(xml_output)
        if events:
            self.logger.debug(f"Retrieved {len(events)} raw events from {self.log_name}.")
        return events

    def update_checkpoint(self, last_successful_record_id: int):
        """Advances the checkpoint only after successful downstream processing."""
        if last_successful_record_id > self.current_checkpoint:
            self.checkpoint_manager.save_checkpoint(last_successful_record_id)
            self.current_checkpoint = last_successful_record_id

    def shutdown(self):
        self.logger.info("Shutting down WindowsEventCollector.")

    def _parse_wevtutil_xml(self, xml_string: str) -> List[Dict[str, Any]]:
        """Parses multiple concatenated Event XML tags returned by wevtutil."""
        wrapped_xml = f"<Events>{xml_string}</Events>"
        parsed_events = []
        try:
            root = ET.fromstring(wrapped_xml)
            namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            
            for event in root.findall(f"{namespace}Event"):
                system = event.find(f"{namespace}System")
                if system is None:
                    continue
                
                event_data = {
                    "raw_xml": ET.tostring(event, encoding="unicode")
                }
                
                provider = system.find(f"{namespace}Provider")
                if provider is not None:
                    event_data["provider"] = provider.get("Name")
                    
                event_id_elem = system.find(f"{namespace}EventID")
                if event_id_elem is not None and event_id_elem.text:
                    event_data["event_id"] = int(event_id_elem.text)
                    
                record_id_elem = system.find(f"{namespace}EventRecordID")
                if record_id_elem is not None and record_id_elem.text:
                    event_data["record_id"] = int(record_id_elem.text)
                    
                time_created_elem = system.find(f"{namespace}TimeCreated")
                if time_created_elem is not None:
                    event_data["timestamp"] = time_created_elem.get("SystemTime")
                    
                computer_elem = system.find(f"{namespace}Computer")
                if computer_elem is not None:
                    event_data["computer"] = computer_elem.text
                    
                level_elem = system.find(f"{namespace}Level")
                if level_elem is not None and level_elem.text:
                    event_data["level"] = int(level_elem.text)
                    
                task_elem = system.find(f"{namespace}Task")
                if task_elem is not None and task_elem.text:
                    event_data["task"] = int(task_elem.text)
                    
                keywords_elem = system.find(f"{namespace}Keywords")
                if keywords_elem is not None and keywords_elem.text:
                    event_data["keywords"] = keywords_elem.text

                event_data_elem = event.find(f"{namespace}EventData")
                if event_data_elem is not None:
                    data_dict = {}
                    for data_elem in event_data_elem.findall(f"{namespace}Data"):
                        name = data_elem.get("Name")
                        if name:
                            data_dict[name] = data_elem.text

                    target_user = data_dict.get("TargetUserName")
                    if target_user and target_user.strip() and target_user.strip() != "-":
                        event_data["username"] = target_user.strip()
                    elif data_dict.get("SubjectUserName") and data_dict["SubjectUserName"].strip() and data_dict["SubjectUserName"].strip() != "-":
                        event_data["username"] = data_dict["SubjectUserName"].strip()

                    ip_addr = data_dict.get("IpAddress")
                    if ip_addr and ip_addr.strip() and ip_addr.strip() != "-":
                        event_data["source_ip"] = ip_addr.strip()

                    logon_type = data_dict.get("LogonType")
                    if logon_type and logon_type.strip() and logon_type.strip() != "-":
                        raw_lt = logon_type.strip()
                        try:
                            event_data["logon_type"] = int(raw_lt)
                        except ValueError:
                            event_data["logon_type"] = raw_lt

                    # Extract Process Creation attributes (Event 4688 / Sysmon 1 / PowerShell 4104)
                    cmd_line = data_dict.get("CommandLine") or data_dict.get("ScriptBlockText")
                    if cmd_line and cmd_line.strip() and cmd_line.strip() != "-":
                        event_data["command_line"] = cmd_line.strip()

                    proc_name = data_dict.get("NewProcessName") or data_dict.get("Image")
                    if proc_name and proc_name.strip() and proc_name.strip() != "-":
                        event_data["process_name"] = proc_name.strip()

                    parent_proc = data_dict.get("ParentProcessName") or data_dict.get("ParentImage")
                    if parent_proc and parent_proc.strip() and parent_proc.strip() != "-":
                        event_data["parent_process_name"] = parent_proc.strip()

                    proc_id = data_dict.get("ProcessId")
                    if proc_id and proc_id.strip() and proc_id.strip() != "-":
                        event_data["process_id"] = proc_id.strip()

                if "record_id" in event_data:

                    parsed_events.append(event_data)
                    
        except ET.ParseError as e:
            self.logger.error(f"XML parse error in event batch: {e}")
            
        return parsed_events
