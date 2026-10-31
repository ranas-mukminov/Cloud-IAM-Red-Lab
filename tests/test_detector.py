import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lab"))
from detector import (find_admin_paths, find_assumption_chains, find_multi_hop_chains, find_privilege_granting_roles, find_wildcard_policies, load)  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data" / "simulated_iam.json"


class TestDetector(unittest.TestCase):
    def setUp(self):
        self.data = load(DATA)

    def test_admin_path_from_developer(self):
        paths = find_admin_paths(self.data)
        chains = [p["chain"] for p in paths]
        self.assertIn(["lab-developer", "lab-deployer", "lab-admin"], chains)

    def test_no_admin_path_from_auditor(self):
        paths = [p for p in find_admin_paths(self.data) if p["start"] == "lab-auditor"]
        self.assertEqual(paths, [])

    def test_privilege_granting_role_flagged(self):
        roles = {r["role"]: r["actions"] for r in find_privilege_granting_roles(self.data)}
        self.assertIn("lab-orphan", roles)
        self.assertIn("iam:AttachUserPolicy", roles["lab-orphan"])

    def test_safe_role_not_flagged(self):
        roles = {r["role"] for r in find_privilege_granting_roles(self.data)}
        self.assertNotIn("lab-auditor", roles)

    def test_chains_are_cycle_safe(self):
        # A self-referential chain must terminate, not loop forever.
        data = json.loads(json.dumps(self.data))
        data["roles"]["lab-developer"]["can_assume"].append("lab-developer")
        chains = find_assumption_chains(data, "lab-developer")
        self.assertTrue(all(len(c) == len(set(c)) for c in chains))


if __name__ == "__main__":
    unittest.main()


class TestNewPatterns(unittest.TestCase):
    def setUp(self):
        self.data = load(DATA)

    def test_multi_hop_chain_found(self):
        chains = [c["chain"] for c in find_multi_hop_chains(self.data)]
        self.assertIn(["lab-junior", "lab-mid", "lab-senior", "lab-admin"], chains)

    def test_wildcard_role_flagged(self):
        roles = {r["role"]: r["actions"] for r in find_wildcard_policies(self.data)}
        self.assertIn("lab-wildcard", roles)
        self.assertIn("iam:*", roles["lab-wildcard"])

    def test_safe_role_not_wildcard(self):
        roles = {r["role"] for r in find_wildcard_policies(self.data)}
        self.assertNotIn("lab-auditor", roles)

    def test_original_admin_path_still_found(self):
        chains = [p["chain"] for p in find_admin_paths(self.data)]
        self.assertIn(["lab-developer", "lab-deployer", "lab-admin"], chains)
