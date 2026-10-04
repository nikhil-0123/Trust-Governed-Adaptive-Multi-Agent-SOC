import json
import math
import uuid
from datetime import datetime, timezone
import os

class AssessmentConfigError(Exception):
    pass

class AssessmentEngine:
    def __init__(self, config_path: str = None):
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), "assessment_config.json")
        try:
            with open(config_path, "r") as f:
                self.config = json.load(f)
        except Exception as e:
            raise AssessmentConfigError(f"Failed to load config: {e}")
            
        required_keys = ["config_version", "formula_version", "factors", "evidence_quality", "categorical_normalization", "feature_normalization"]
        for k in required_keys:
            if k not in self.config:
                raise AssessmentConfigError(f"Missing required config key: {k}")

    def process_incident(self, conn, incident_id: str) -> str:
        # 1. Fetch incident severity
        cursor = conn.execute("SELECT max_severity FROM incidents WHERE incident_id = ?", (incident_id,))
        inc_row = cursor.fetchone()
        if not inc_row:
            raise ValueError(f"Incident {incident_id} not found.")
        max_severity = inc_row["max_severity"]
        
        # 2. Fetch event stats for Trust
        cursor = conn.execute("""
            SELECT e.data
            FROM events e
            JOIN incident_evidence ie ON e.detection_event_id = ie.detection_event_id
            WHERE ie.incident_id = ?
        """, (incident_id,))
        event_rows = cursor.fetchall()
        event_count = len(event_rows)
        
        confidence_values = []
        for row in event_rows:
            try:
                data = json.loads(row["data"])
                if "confidence" in data and isinstance(data["confidence"], (int, float)):
                    confidence_values.append(float(data["confidence"]))
            except Exception:
                pass
                
        # 3. Fetch MITRE for Risk
        cursor = conn.execute("""
            SELECT DISTINCT technique_id 
            FROM threat_context
            WHERE incident_id = ?
        """, (incident_id,))
        mitre_rows = cursor.fetchall()
        mapped_techniques = [r["technique_id"] for r in mitre_rows]
        
        # --- TRUST CALCULATION ---
        eq_config = self.config["evidence_quality"]
        k_factor = self.config["feature_normalization"]["evidence_volume_k_factor"]
        
        e_vol = min(1.0, 1.0 - math.exp(-k_factor * event_count))
        e_conf = sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
        
        e_raw = (e_vol * eq_config["volume_weight"]) + (e_conf * eq_config["confidence_weight"])
        e_val = max(0.0, min(1.0, e_raw))
        
        trust_factors_config = self.config["factors"]["trust"]
        available_trust_factors = {"E": e_val}
        
        trust_num = 0.0
        trust_den = 0.0
        effective_trust_weights = {}
        for f_name, f_val in available_trust_factors.items():
            w = trust_factors_config.get(f_name, 0.0)
            trust_num += f_val * w
            trust_den += w
            effective_trust_weights[f_name] = w
            
        trust_score = trust_num / trust_den if trust_den > 0 else None
        
        # --- RISK CALCULATION ---
        severity_map = self.config["categorical_normalization"]["severity"]
        s_val = severity_map.get(max_severity.upper())
        if s_val is None:
            raise ValueError(f"Invalid severity '{max_severity}' cannot be normalized.")
            
        risk_factors_config = self.config["factors"]["risk"]
        available_risk_factors = {"S": s_val}
        
        c_val = None
        if len(mapped_techniques) > 0:
            c_base = self.config["feature_normalization"]["mitre_technique_base_weight"]
            c_val = min(1.0, len(mapped_techniques) * c_base)
            available_risk_factors["C"] = c_val
            
        risk_num = 0.0
        risk_den = 0.0
        effective_risk_weights = {}
        for f_name, f_val in available_risk_factors.items():
            w = risk_factors_config.get(f_name, 0.0)
            risk_num += f_val * w
            risk_den += w
            effective_risk_weights[f_name] = w
            
        risk_score = risk_num / risk_den if risk_den > 0 else None
        
        # --- STATUS ---
        status = "COMPLETED"
        if trust_score is None and risk_score is None:
            status = "INSUFFICIENT_DATA"
            
        # --- EXPLANATIONS & SNAPSHOTS ---
        input_snapshot = {
            "incident_id": incident_id,
            "max_severity": max_severity,
            "detection_event_count": event_count,
            "detection_confidence_values": confidence_values,
            "mapped_technique_ids": mapped_techniques,
            "mitre_availability": "AVAILABLE" if c_val is not None else "UNAVAILABLE",
            "available_trust_factors": list(available_trust_factors.keys()),
            "available_risk_factors": list(available_risk_factors.keys()),
            "raw_factor_inputs": {
                "E_vol": e_vol,
                "E_conf": e_conf,
                "S": max_severity,
                "Distinct_C_Count": len(mapped_techniques)
            },
            "calculation_parameters": {
                "evidence_volume_k_factor": self.config["feature_normalization"]["evidence_volume_k_factor"],
                "volume_weight": self.config["evidence_quality"]["volume_weight"],
                "confidence_weight": self.config["evidence_quality"]["confidence_weight"],
                "confidence_aggregation": self.config["evidence_quality"]["confidence_aggregation"],
                "mitre_technique_base_weight": self.config["feature_normalization"]["mitre_technique_base_weight"],
                "severity_normalization": self.config["categorical_normalization"]["severity"]
            }
        }
        
        trust_explanation = {
            "normalized_E": e_val,
            "available_factors": list(available_trust_factors.keys()),
            "excluded_factors": ["V", "R", "H"],
            "configured_weights": trust_factors_config,
            "effective_weights": effective_trust_weights,
            "numerator": trust_num,
            "denominator": trust_den,
            "final_trust_score": trust_score
        }
        
        risk_explanation = {
            "normalized_S": s_val,
            "normalized_C": c_val,
            "available_factors": list(available_risk_factors.keys()),
            "excluded_factors": ["A", "I"] + (["C"] if c_val is None else []),
            "configured_weights": risk_factors_config,
            "effective_weights": effective_risk_weights,
            "numerator": risk_num,
            "denominator": risk_den,
            "final_risk_score": risk_score
        }
        
        # --- PERSISTENCE ---
        assessment_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        conn.execute("""
            INSERT INTO assessments (
                assessment_id, incident_id, trust_score, risk_score, status, 
                formula_version, config_version, input_snapshot, 
                trust_explanation, risk_explanation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            assessment_id, incident_id, trust_score, risk_score, status,
            self.config["formula_version"], self.config["config_version"],
            json.dumps(input_snapshot), json.dumps(trust_explanation), json.dumps(risk_explanation), now
        ))
        
        conn.execute("""
            UPDATE incidents SET latest_assessment_id = ? WHERE incident_id = ?
        """, (assessment_id, incident_id))
        
        return status
