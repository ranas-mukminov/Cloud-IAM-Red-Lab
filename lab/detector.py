"""Detector for privilege-escalation paths in simulated IAM data.

The detector walks role-assumption chains and policy actions in a
local JSON file. It makes no network calls and knows nothing about
any real cloud. A finding is a path in the fictional data, and the
report says so.
"""

import argparse
import json
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text())


def find_assumption_chains(data, start):
    """Return all assumption chains from *start* (depth-first, cycle-safe)."""
    roles = data["roles"]
    chains = []

    def walk(role, path, seen):
        if role in seen:
            return
        seen = seen | {role}
        path = path + [role]
        chains.append(path)
        for nxt in roles.get(role, {}).get("can_assume", []):
            walk(nxt, path, seen)

    walk(start, [], set())
    return chains


def find_privilege_granting_roles(data):
    """Roles whose policies include a privilege-granting action."""
    granting = set(data.get("privilege_granting_actions", []))
    out = []
    for role, info in data["roles"].items():
        actions = []
        for policy in info.get("policies", []):
            actions.extend(data["policies"].get(policy, []))
        hits = sorted(set(actions) & granting)
        if hits:
            out.append({"role": role, "actions": hits})
    return out


def find_admin_paths(data):
    """Chains from any role that end at a role holding the admin policy."""
    admin_roles = {
        role for role, info in data["roles"].items()
        if data.get("admin_policy") in info.get("policies", [])
    }
    out = []
    for start in data["roles"]:
        for chain in find_assumption_chains(data, start):
            if len(chain) > 1 and chain[-1] in admin_roles:
                out.append({"start": start, "chain": chain, "admin_role": chain[-1]})
    return out


def find_wildcard_policies(data):
    """Roles whose policies contain a wildcard action (e.g. iam:* or *)."""
    out = []
    for role, info in data["roles"].items():
        actions = []
        for policy in info.get("policies", []):
            actions.extend(data["policies"].get(policy, []))
        hits = sorted(a for a in set(actions) if "*" in a)
        if hits:
            out.append({"role": role, "actions": hits})
    return out


def find_multi_hop_chains(data, min_length=4):
    """Assumption chains of at least *min_length* roles.

    Long chains are the interesting case: every hop individually
    looks low-privilege, and only the full chain reaches admin.
    """
    out = []
    for start in data["roles"]:
        for chain in find_assumption_chains(data, start):
            if len(chain) >= min_length:
                out.append({"start": start, "chain": chain})
    return out


def report(data):
    return {
        "scope": "simulated fictional IAM data only; no real cloud account",
        "admin_paths": find_admin_paths(data),
        "privilege_granting_roles": find_privilege_granting_roles(data),
        "wildcard_policies": find_wildcard_policies(data),
        "multi_hop_chains": find_multi_hop_chains(data),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    args = parser.parse_args(argv)
    rep = report(load(args.data))
    print(json.dumps(rep, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
