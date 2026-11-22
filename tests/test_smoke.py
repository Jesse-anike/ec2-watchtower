import json
import unittest

from main import analyze


class Ec2WatchtowerTests(unittest.TestCase):
    def test_sample_detects_expected_configuration_findings(self):
        from pathlib import Path
        sample = (Path(__file__).resolve().parents[1] / "sample.json").read_text(encoding="utf-8")
        report = analyze(sample)
        self.assertEqual(report["instances_reviewed"], 2)
        risks = {finding["risk"] for finding in report["findings"]}
        self.assertIn("public_ipv4_assigned", risks)
        self.assertIn("imds_v2_not_required", risks)
        self.assertIn("no_instance_profile", risks)

    def test_secure_instance_has_no_findings(self):
        secure = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-secure",
                    "State": {"Name": "stopped"},
                    "MetadataOptions": {"HttpTokens": "required"},
                    "IamInstanceProfile": {"Arn": "arn:aws:iam::000000000000:instance-profile/role"}
                }]
            }]
        }
        report = analyze(json.dumps(secure))
        self.assertEqual(report["finding_count"], 0)

    def test_invalid_json_is_reported(self):
        self.assertIn("error", analyze("{not-json"))

    def test_empty_export_is_valid(self):
        report = analyze("{}")
        self.assertEqual(report["instances_reviewed"], 0)
        self.assertEqual(report["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
