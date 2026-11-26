import unittest
import os
import tempfile
import sqlite3
import json
import time
from datetime import datetime, timezone

from app.database import init_db, get_db_connection
from app.mitre import MitreEngine, MitreCatalogError
from app.mitre_worker import MitreWorker
from app.worker import FusionWorker
from app.main import startup_event, shutdown_event

class TestMitreCatalog(unittest.TestCase):
    def test_invalid_catalog_missing_fields(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            json.dump({
                "mitre_version": "v15.0",
                "mappings": [
                    {
                        "mapping_rule_id": "rule_1",
                        "detection_type": "bad"
                        # missing technique_id etc
                    }
                ]
            }, f)
            temp_path = f.name

        with self.assertRaises(MitreCatalogError):
            MitreEngine(catalog_path=temp_path)
        os.unlink(temp_path)

    def test_invalid_technique_id(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            json.dump({
                "mitre_version": "v15.0",
                "mappings": [
                    {
                        "mapping_rule_id": "rule_1",
                        "detection_type": "bad",
                        "technique_id": "bad-id",
                        "technique_name": "name",
                        "tactic": "tactic"
                    }
                ]
            }, f)
            temp_path = f.name

        with self.assertRaises(MitreCatalogError):
            MitreEngine(catalog_path=temp_path)
        os.unlink(temp_path)

    def test_duplicate_mapping_rule_id(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            json.dump({
                "mitre_version": "v15.0",
                "mappings": [
                    {
                        "mapping_rule_id": "rule_1",
                        "detection_type": "t1",
                        "technique_id": "T1110",
                        "technique_name": "name",
                        "tactic": "tactic"
                    },
                    {
                        "mapping_rule_id": "rule_1",
                        "detection_type": "t2",
                        "technique_id": "T1111",
                        "technique_name": "name2",
                        "tactic": "tactic2"
                    }
                ]
            }, f)
            temp_path = f.name

        with self.assertRaisesRegex(MitreCatalogError, "Duplicate mapping_rule_id"):
            MitreEngine(catalog_path=temp_path)
        os.unlink(temp_path)

    def test_duplicate_detection_type_ambiguity(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            json.dump({
                "mitre_version": "v15.0",
                "mappings": [
                    {
                        "mapping_rule_id": "rule_1",
                        "detection_type": "ambiguous",
                        "technique_id": "T1110",
                        "technique_name": "name",
                        "tactic": "tactic"
                    },
                    {
                        "mapping_rule_id": "rule_2",
                        "detection_type": "ambiguous",
                        "technique_id": "T1111",
                        "technique_name": "name2",
                        "tactic": "tactic2"
                    }
                ]
            }, f)
            temp_path = f.name

        with self.assertRaisesRegex(MitreCatalogError, "Duplicate detection_type"):
            MitreEngine(catalog_path=temp_path)
        os.unlink(temp_path)


class TestMitreEngineDB(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.environ["SOC_DB_PATH"] = self.db_path
        import app.database
        app.database.DB_PATH = self.db_path
        app.database.init_db()
        os.close(self.db_fd)
        self.engine = MitreEngine()

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except:
            pass

    def _insert_event_and_incident(self, conn, event_id, det_type):
        data = {
            "detection_type": det_type
        }
        conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", (event_id, json.dumps(data)))
        conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-1",))
        conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-1", event_id))
        conn.commit()

    def test_known_mapping(self):
        with get_db_connection() as conn:
            self._insert_event_and_incident(conn, "e1", "brute_force")
            res = self.engine.process_event(conn, "e1")
            self.assertEqual(res, "MAPPED")
            conn.commit()

            cursor = conn.execute("SELECT * FROM threat_context WHERE incident_id = 'inc-1'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["technique_id"], "T1110")
            self.assertEqual(row["mapping_method"], "deterministic_rule")

    def test_windows_bruteforce_bridge_mapping(self):
        with get_db_connection() as conn:
            self._insert_event_and_incident(conn, "e1", "windows_bruteforce_rule")
            res = self.engine.process_event(conn, "e1")
            self.assertEqual(res, "MAPPED")
            conn.commit()

            cursor = conn.execute("SELECT * FROM threat_context")
            row = cursor.fetchone()
            self.assertEqual(row["technique_id"], "T1110")

    def test_unmapped_detection(self):
        with get_db_connection() as conn:
            self._insert_event_and_incident(conn, "e1", "unknown_type")
            res = self.engine.process_event(conn, "e1")
            self.assertEqual(res, "UNMAPPED")
            conn.commit()

            cursor = conn.execute("SELECT COUNT(*) as c FROM threat_context")
            self.assertEqual(cursor.fetchone()["c"], 0)

    def test_duplicate_evidence(self):
        with get_db_connection() as conn:
            self._insert_event_and_incident(conn, "e1", "brute_force")
            self.engine.process_event(conn, "e1")

            # Reprocessing same event appends to evidence OR ignores if unique
            self.engine.process_event(conn, "e1")
            conn.commit()

            cursor = conn.execute("SELECT COUNT(*) as c FROM threat_context")
            self.assertEqual(cursor.fetchone()["c"], 1)

            cursor = conn.execute("SELECT COUNT(*) as c FROM threat_context_evidence")
            self.assertEqual(cursor.fetchone()["c"], 1)

    def test_multiple_evidence_one_technique(self):
        with get_db_connection() as conn:
            self._insert_event_and_incident(conn, "e1", "brute_force")
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e2", json.dumps({"detection_type": "brute_force"})))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-1", "e2"))
            conn.commit()

            self.engine.process_event(conn, "e1")
            self.engine.process_event(conn, "e2")
            conn.commit()

            # One context row
            cursor = conn.execute("SELECT COUNT(*) as c FROM threat_context")
            self.assertEqual(cursor.fetchone()["c"], 1)

            # Two evidence rows
            cursor = conn.execute("SELECT COUNT(*) as c FROM threat_context_evidence")
            self.assertEqual(cursor.fetchone()["c"], 2)

    def test_process_rules_mappings(self):
        with get_db_connection() as conn:
            # Test PowerShell T1059.001
            self._insert_event_and_incident(conn, "e-ps", "windows_powershell_execution")
            res_ps = self.engine.process_event(conn, "e-ps")
            self.assertEqual(res_ps, "MAPPED")

            # Test LOLBin T1105
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e-lolbin", json.dumps({"detection_type": "windows_lolbin_download"})))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-1", "e-lolbin"))
            res_lol = self.engine.process_event(conn, "e-lolbin")
            self.assertEqual(res_lol, "MAPPED")

            conn.commit()

            cursor = conn.execute("SELECT technique_id FROM threat_context WHERE incident_id = 'inc-1' ORDER BY technique_id")
            tech_ids = [r["technique_id"] for r in cursor.fetchall()]
            self.assertIn("T1059.001", tech_ids)
            self.assertIn("T1105", tech_ids)

    def test_unknown_technique_override_falls_back_to_default(self):
        with get_db_connection() as conn:
            data = {
                "detection_type": "windows_reconnaissance",
                "evidence": {"mitre_technique_id": "T9999"}
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e_unk", json.dumps(data)))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-unk",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-unk", "e_unk"))
            conn.commit()

            res = self.engine.process_event(conn, "e_unk")
            self.assertEqual(res, "MAPPED")
            conn.commit()

            cursor = conn.execute("SELECT * FROM threat_context WHERE incident_id = 'inc-unk'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["technique_id"], "T1082")  # Fell back to default for windows_reconnaissance

    def test_unrelated_technique_override_rejected_and_falls_back(self):
        with get_db_connection() as conn:
            # T1486 is Ransomware (tactic Impact), but detection_type is windows_reconnaissance (tactic Discovery)
            data = {
                "detection_type": "windows_reconnaissance",
                "evidence": {"mitre_technique_id": "T1486"}
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e_unrel", json.dumps(data)))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-unrel",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-unrel", "e_unrel"))
            conn.commit()

            res = self.engine.process_event(conn, "e_unrel")
            self.assertEqual(res, "MAPPED")
            conn.commit()

            cursor = conn.execute("SELECT * FROM threat_context WHERE incident_id = 'inc-unrel'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["technique_id"], "T1082")  # T1486 rejected due to tactic mismatch; fell back to T1082

    def test_compatible_technique_override_accepted(self):
        with get_db_connection() as conn:
            # T1033 is User Discovery (tactic Discovery), matching windows_reconnaissance (Discovery)
            data = {
                "detection_type": "windows_reconnaissance",
                "evidence": {"mitre_technique_id": "T1033"}
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e_comp", json.dumps(data)))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-comp",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-comp", "e_comp"))
            conn.commit()

            res = self.engine.process_event(conn, "e_comp")
            self.assertEqual(res, "MAPPED")
            conn.commit()

            cursor = conn.execute("SELECT * FROM threat_context WHERE incident_id = 'inc-comp'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["technique_id"], "T1033")  # Compatible tactic override accepted

    def test_malformed_evidence_handled_gracefully(self):
        with get_db_connection() as conn:
            # Non-dict evidence string
            data = {
                "detection_type": "windows_reconnaissance",
                "evidence": "invalid-non-dict-evidence"
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e_mal", json.dumps(data)))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-mal",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-mal", "e_mal"))
            conn.commit()

            res = self.engine.process_event(conn, "e_mal")
            self.assertEqual(res, "MAPPED")
            conn.commit()

            cursor = conn.execute("SELECT * FROM threat_context WHERE incident_id = 'inc-mal'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["technique_id"], "T1082")

    def test_unknown_detection_type_and_unknown_override_unmapped(self):
        with get_db_connection() as conn:
            data = {
                "detection_type": "completely_unknown_attack_type",
                "evidence": {"mitre_technique_id": "T9999"}
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e_unk2", json.dumps(data)))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-unk2",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-unk2", "e_unk2"))
            conn.commit()

            res = self.engine.process_event(conn, "e_unk2")
            self.assertEqual(res, "UNMAPPED")
            conn.commit()

    def test_unknown_detection_type_with_valid_catalog_override_rejected(self):
        with get_db_connection() as conn:
            # Detection type unknown, but override is a real technique (T1110 Brute Force)
            data = {
                "detection_type": "unknown_custom_attack",
                "evidence": {"mitre_technique_id": "T1110"}
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e_unk_override", json.dumps(data)))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-unk-ov",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-unk-ov", "e_unk_override"))
            conn.commit()

            # Must reject arbitrary override on unknown detection type
            res = self.engine.process_event(conn, "e_unk_override")
            self.assertEqual(res, "UNMAPPED")
            conn.commit()

    def test_unauthorized_technique_override_for_reconnaissance_falls_back(self):
        with get_db_connection() as conn:
            # T1105 is Ingress Tool Transfer (C2), unauthorized for windows_reconnaissance
            data = {
                "detection_type": "windows_reconnaissance",
                "evidence": {"mitre_technique_id": "T1105"}
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e_unauth_recon", json.dumps(data)))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-unauth-recon",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-unauth-recon", "e_unauth_recon"))
            conn.commit()

            res = self.engine.process_event(conn, "e_unauth_recon")
            self.assertEqual(res, "MAPPED")
            conn.commit()

            cursor = conn.execute("SELECT * FROM threat_context WHERE incident_id = 'inc-unauth-recon'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["technique_id"], "T1082")  # Falls back to allowed default

    def test_allowed_technique_t1082_and_t1033_interchangeable_for_discovery(self):
        with get_db_connection() as conn:
            # windows_user_discovery overriding with T1082 (System Information Discovery)
            data1 = {
                "detection_type": "windows_user_discovery",
                "evidence": {"mitre_technique_id": "T1082"}
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e_user_to_sys", json.dumps(data1)))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-user-sys",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-user-sys", "e_user_to_sys"))

            # windows_reconnaissance overriding with T1033 (User Discovery)
            data2 = {
                "detection_type": "windows_reconnaissance",
                "evidence": {"mitre_technique_id": "T1033"}
            }
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e_sys_to_user", json.dumps(data2)))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-sys-user",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-sys-user", "e_sys_to_user"))
            conn.commit()

            self.assertEqual(self.engine.process_event(conn, "e_user_to_sys"), "MAPPED")
            self.assertEqual(self.engine.process_event(conn, "e_sys_to_user"), "MAPPED")
            conn.commit()

            row1 = conn.execute("SELECT technique_id FROM threat_context WHERE incident_id = 'inc-user-sys'").fetchone()
            row2 = conn.execute("SELECT technique_id FROM threat_context WHERE incident_id = 'inc-sys-user'").fetchone()
            self.assertEqual(row1["technique_id"], "T1082")
            self.assertEqual(row2["technique_id"], "T1033")



class TestMitreWorkerIntegration(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.environ["SOC_DB_PATH"] = self.db_path
        os.environ["MITRE_POLL_INTERVAL_SECONDS"] = "1"
        import app.database
        app.database.DB_PATH = self.db_path
        app.database.init_db()
        os.close(self.db_fd)

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except:
            pass

    def test_step_7_8_transaction_isolation(self):
        # Even if mitre worker fails, step 7 is already committed
        with get_db_connection() as conn:
            # Emulate step 7 commitment
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e1", "{}"))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-1",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-1", "e1"))
            conn.execute("INSERT INTO threat_context_state (detection_event_id, status, updated_at) VALUES (?, 'PENDING', datetime('now'))", ("e1",))
            conn.commit()

        worker = MitreWorker()
        # Destroy catalog to force failure
        worker.engine = None

        worker.process_batch()

        # Verify step 7 remains
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) as c FROM incidents")
            self.assertEqual(cursor.fetchone()["c"], 1)

            cursor = conn.execute("SELECT status FROM threat_context_state WHERE detection_event_id = 'e1'")
            self.assertEqual(cursor.fetchone()["status"], "FAILED")

    def test_stale_processing_recovery(self):
        with get_db_connection() as conn:
            conn.execute("INSERT INTO events (detection_event_id, data) VALUES (?, ?)", ("e1", json.dumps({"detection_type": "brute_force"})))
            conn.execute("INSERT INTO incidents (incident_id, created_at, updated_at, first_seen, last_seen, max_severity, status) VALUES (?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), 'high', 'OPEN')", ("inc-1",))
            conn.execute("INSERT INTO incident_evidence (incident_id, detection_event_id) VALUES (?, ?)", ("inc-1", "e1"))

            # Stale processing state (2 hours ago)
            conn.execute("INSERT INTO threat_context_state (detection_event_id, status, updated_at) VALUES (?, 'PROCESSING', datetime('now', '-2 hour'))", ("e1",))
            conn.commit()

        worker = MitreWorker()
        worker.process_batch()

        with get_db_connection() as conn:
            cursor = conn.execute("SELECT status FROM threat_context_state WHERE detection_event_id = 'e1'")
            self.assertEqual(cursor.fetchone()["status"], "MAPPED")

    def test_worker_start_stop(self):
        orig_disable = os.environ.pop("DISABLE_STARTUP_WORKERS", None)
        try:
            startup_event()
            from app.main import mitre_worker, fusion_worker
            self.assertIsNotNone(mitre_worker)
            self.assertTrue(mitre_worker.is_alive())

            shutdown_event()
            self.assertFalse(mitre_worker.is_alive())
        finally:
            if orig_disable is not None:
                os.environ["DISABLE_STARTUP_WORKERS"] = orig_disable

    def test_mitre_matrix_api(self):
        from fastapi.testclient import TestClient
        from app.main import app
        tok = os.getenv("SOC_API_TOKEN", "dev-token-123")
        client = TestClient(app)
        res = client.get("/api/v1/mitre/matrix", headers={"Authorization": f"Bearer {tok}"})
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

if __name__ == '__main__':

    unittest.main()
