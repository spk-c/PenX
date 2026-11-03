"""PX-002 historical metadata v1/v2/v3 decoder downgrade guard.

These synthetic fixtures never touch a database or network. Old contracts
must remain readable but new-version fields cannot be smuggled into old
payloads and silently discarded.
"""
import json
import unittest

from penx_app.domain.scan_models import ScanResult


def old_row():
    return {"id":"nmap","name":"Nmap","status":"FAILED","evidence":False}


class HistoricalMetadataDowngradeTests(unittest.TestCase):
    def test_legitimate_v1_v2_and_v3_recover_without_invented_reasons(self):
        for version in (1,2,3):
            row=old_row()
            if version==3:
                row["events"]=[]
            payload={"version":version,"adapters":[row]}
            with self.subTest(version=version):
                parsed=ScanResult.from_metadata(json.dumps(payload))
                self.assertEqual(parsed.results[0].status,"FAILED")
                self.assertFalse(parsed.results[0].evidence)
                self.assertIsNone(parsed.results[0].reason)

    def test_legacy_version_cannot_hide_newer_top_level_plan(self):
        for version in (1,2):
            payload={"version":version,"adapters":[old_row()],
                     "plan":{"profile_id":"standard","profile_version":1,
                             "max_parallelism":1,"global_budget_seconds":None}}
            with self.subTest(version=version),self.assertRaises(ValueError):
                ScanResult.from_metadata(json.dumps(payload))

    def test_unknown_top_level_field_is_not_silently_ignored(self):
        for version in (1,2,3):
            payload={"version":version,"adapters":[old_row()],"verified":True}
            with self.subTest(version=version),self.assertRaises(ValueError):
                ScanResult.from_metadata(json.dumps(payload))

    def test_unknown_per_adapter_field_is_not_silently_ignored(self):
        for version in (1,2,3):
            payload={"version":version,"adapters":[{**old_row(),"is_clean":True}]}
            with self.subTest(version=version),self.assertRaises(ValueError):
                ScanResult.from_metadata(json.dumps(payload))

    def test_v2_records_and_v3_reason_remain_legal(self):
        v2={"version":2,"adapters":[{**old_row(),"records":[]}]}
        v3={"version":3,"adapters":[{**old_row(),"events":[],
                                       "reason":"missing_dependency"}]}
        self.assertEqual(ScanResult.from_metadata(json.dumps(v2)).results[0].status,"FAILED")
        self.assertEqual(ScanResult.from_metadata(json.dumps(v3)).results[0].reason,
                         "missing_dependency")

if __name__=="__main__":
    unittest.main()
