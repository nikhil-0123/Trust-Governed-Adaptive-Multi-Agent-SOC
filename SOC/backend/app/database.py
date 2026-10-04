import sqlite3
import os
import contextlib

DB_PATH = os.getenv("SOC_DB_PATH", "soc_central.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        # Enforce foreign keys
        conn.execute("PRAGMA foreign_keys = ON")
        
        # Existing table from Step 6
        conn.execute('''
            CREATE TABLE IF NOT EXISTS events (
                detection_event_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # New Step 7 Tables
        conn.execute('''
            CREATE TABLE IF NOT EXISTS fusion_event_state (
                detection_event_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                last_error TEXT,
                updated_at TIMESTAMP,
                FOREIGN KEY(detection_event_id) REFERENCES events(detection_event_id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                max_severity TEXT NOT NULL,
                status TEXT NOT NULL,
                latest_assessment_id TEXT, -- Application-maintained pointer to the newest successful assessment row, NOT a strictly enforced DB foreign key.
                latest_analysis_id TEXT    -- Application-maintained pointer to the newest successful analysis row.
            )
        ''')
        
        try:
            conn.execute("ALTER TABLE incidents ADD COLUMN latest_assessment_id TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            conn.execute("ALTER TABLE incidents ADD COLUMN latest_analysis_id TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS incident_evidence (
                incident_id TEXT NOT NULL,
                detection_event_id TEXT NOT NULL,
                PRIMARY KEY (incident_id, detection_event_id),
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id),
                FOREIGN KEY(detection_event_id) REFERENCES events(detection_event_id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS incident_entities (
                incident_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_value TEXT NOT NULL,
                PRIMARY KEY (incident_id, entity_type, entity_value),
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            )
        ''')
        
        # Step 8 Tables
        conn.execute('''
            CREATE TABLE IF NOT EXISTS threat_context_state (
                detection_event_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                last_error TEXT,
                updated_at TIMESTAMP,
                FOREIGN KEY(detection_event_id) REFERENCES events(detection_event_id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS threat_context (
                context_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                technique_name TEXT NOT NULL,
                tactic TEXT NOT NULL,
                mitre_version TEXT NOT NULL,
                mapping_method TEXT NOT NULL,
                UNIQUE(incident_id, technique_id),
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS threat_context_evidence (
                context_id TEXT NOT NULL,
                detection_event_id TEXT NOT NULL,
                mapping_rule_id TEXT NOT NULL,
                PRIMARY KEY (context_id, detection_event_id),
                FOREIGN KEY(context_id) REFERENCES threat_context(context_id),
                FOREIGN KEY(detection_event_id) REFERENCES events(detection_event_id)
            )
        ''')
        
        # Step 7 & 8 Indexes
        conn.execute('CREATE INDEX IF NOT EXISTS idx_fusion_state_status ON fusion_event_state(status, updated_at)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_incidents_status_last_seen ON incidents(status, last_seen)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_incident_entities_lookup ON incident_entities(entity_type, entity_value, incident_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_threat_state_status ON threat_context_state(status, updated_at)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_threat_context_incident ON threat_context(incident_id)')
        
        # Step 9 Tables
        conn.execute('''
            CREATE TABLE IF NOT EXISTS assessment_state (
                incident_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                last_error TEXT,
                updated_at TIMESTAMP,
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                trust_score REAL,
                risk_score REAL,
                status TEXT NOT NULL,
                formula_version TEXT NOT NULL,
                config_version TEXT NOT NULL,
                input_snapshot TEXT NOT NULL,
                trust_explanation TEXT,
                risk_explanation TEXT,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            )
        ''')
        
        # Step 9 Indexes
        conn.execute('CREATE INDEX IF NOT EXISTS idx_assessment_state_status ON assessment_state(status, updated_at)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_assessments_incident ON assessments(incident_id, created_at)')
        
        # Step 10 Tables
        conn.execute('''
            CREATE TABLE IF NOT EXISTS analysis_state (
                incident_id TEXT NOT NULL,
                assessment_id TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                last_error TEXT,
                updated_at TIMESTAMP,
                PRIMARY KEY (incident_id, assessment_id),
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                assessment_id TEXT NOT NULL,
                assessment_snapshot TEXT NOT NULL,
                status TEXT NOT NULL,
                model_provenance TEXT NOT NULL,
                prompt_versions TEXT NOT NULL,
                analysis_output TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            )
        ''')
        
        conn.execute('CREATE INDEX IF NOT EXISTS idx_analysis_state_status ON analysis_state(status, updated_at)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_analyses_incident ON analyses(incident_id, created_at)')
        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_analyses_completed_unique ON analyses(incident_id, assessment_id) WHERE status = \'COMPLETED\'')
        
        conn.commit()
    finally:
        conn.close()

@contextlib.contextmanager
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
