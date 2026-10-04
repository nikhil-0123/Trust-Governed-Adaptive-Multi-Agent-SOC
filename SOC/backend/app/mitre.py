import json
import logging
import os
import re
import uuid
from typing import Dict, Any

logger = logging.getLogger(__name__)

class MitreCatalogError(Exception):
    pass

class MitreEngine:
    def __init__(self, catalog_path: str = None):
        if catalog_path is None:
            catalog_path = os.path.join(os.path.dirname(__file__), "mitre_catalog.json")
        self.catalog_path = catalog_path
        self.mitre_version = ""
        self.rules_by_type: Dict[str, Dict[str, Any]] = {}
        self._load_and_validate_catalog()

    def _load_and_validate_catalog(self):
        if not os.path.exists(self.catalog_path):
            raise MitreCatalogError(f"Catalog file not found: {self.catalog_path}")
            
        try:
            with open(self.catalog_path, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise MitreCatalogError(f"Invalid JSON in catalog: {e}")

        self.mitre_version = data.get("mitre_version")
        if not self.mitre_version or not isinstance(self.mitre_version, str):
            raise MitreCatalogError("mitre_version is missing or invalid.")
            
        mappings = data.get("mappings")
        if not mappings or not isinstance(mappings, list) or len(mappings) == 0:
            raise MitreCatalogError("mappings list is missing or empty.")

        rule_ids = set()
        tech_id_regex = re.compile(r"^T\d{4}(\.\d{3})?$")

        for rule in mappings:
            rule_id = rule.get("mapping_rule_id")
            det_type = rule.get("detection_type")
            tech_id = rule.get("technique_id")
            tech_name = rule.get("technique_name")
            tactic = rule.get("tactic")

            if not all(isinstance(x, str) and x.strip() for x in (rule_id, det_type, tech_id, tech_name, tactic)):
                raise MitreCatalogError(f"Rule missing required string fields: {rule}")

            if rule_id in rule_ids:
                raise MitreCatalogError(f"Duplicate mapping_rule_id: {rule_id}")
            rule_ids.add(rule_id)

            if not tech_id_regex.match(tech_id):
                raise MitreCatalogError(f"Invalid technique_id format: {tech_id}")

            if det_type in self.rules_by_type:
                existing_tech = self.rules_by_type[det_type]["technique_id"]
                if existing_tech != tech_id:
                    raise MitreCatalogError(f"Duplicate detection_type '{det_type}' maps to different techniques: {existing_tech} vs {tech_id}")
                # We can map the same detection_type multiple times to the SAME technique, but here we just take the first one or override. 
                # Wait, "Multiple detection_types may map to the same technique" means diff det_types -> same tech. 
                # If we have same det_type -> same tech (diff rules), which rule applies?
                # The requirement says "detection_type -> exactly one technique".
                
            self.rules_by_type[det_type] = rule

    def process_event(self, conn, detection_event_id: str) -> str:
        # 1. Fetch detection type from events
        cursor = conn.execute("SELECT data FROM events WHERE detection_event_id = ?", (detection_event_id,))
        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Event {detection_event_id} not found in events table.")
            
        try:
            event_data = json.loads(row["data"])
            det_type = event_data.get("detection_type")
        except Exception as e:
            raise ValueError(f"Failed to parse event data: {e}")

        # 2. Check catalog
        if not det_type or det_type not in self.rules_by_type:
            return "UNMAPPED"
            
        rule = self.rules_by_type[det_type]
        
        # 3. Find incident_id
        cursor = conn.execute("SELECT incident_id FROM incident_evidence WHERE detection_event_id = ?", (detection_event_id,))
        inc_row = cursor.fetchone()
        if not inc_row:
            raise ValueError(f"Event {detection_event_id} is not attached to any incident. Run Evidence Fusion first.")
            
        incident_id = inc_row["incident_id"]
        technique_id = rule["technique_id"]
        
        # 4. Check if technique is already on the incident
        cursor = conn.execute("SELECT context_id FROM threat_context WHERE incident_id = ? AND technique_id = ?", (incident_id, technique_id))
        ctx_row = cursor.fetchone()
        
        if ctx_row:
            context_id = ctx_row["context_id"]
        else:
            context_id = str(uuid.uuid4())
            conn.execute("""
                INSERT INTO threat_context (context_id, incident_id, technique_id, technique_name, tactic, mitre_version, mapping_method)
                VALUES (?, ?, ?, ?, ?, ?, 'deterministic_rule')
            """, (context_id, incident_id, technique_id, rule["technique_name"], rule["tactic"], self.mitre_version))
            
        # 5. Insert evidence linkage
        conn.execute("""
            INSERT OR IGNORE INTO threat_context_evidence (context_id, detection_event_id, mapping_rule_id)
            VALUES (?, ?, ?)
        """, (context_id, detection_event_id, rule["mapping_rule_id"]))
        
        return "MAPPED"
