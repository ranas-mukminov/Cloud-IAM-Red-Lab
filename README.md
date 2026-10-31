# Cloud-IAM-Red-Lab

A cloud IAM privilege-escalation lab that runs entirely on simulated
data. No cloud account, no credentials, no API calls, no LocalStack.

## Why simulation

Real cloud privilege-escalation testing requires a sandbox account you
own, with guardrails, and even then a mistake can affect real resources.
This lab removes that risk: the "cloud" is a JSON file of fictional
roles and policies, and the detector is a local graph walk over that
file. The skill being practised — reading a policy, following a trust
chain, and spotting the step that grants more than intended — is the
same skill, without the blast radius.

## What is in the lab

- `data/simulated_iam.json` — fictional accounts, roles, trust
  relationships and policies. Every name is `lab-*`; there is no real
  account ID, no real ARN, no real key.
- `lab/detector.py` — finds escalation paths: a role that can assume
  another role, a policy that allows privilege-granting actions, and
  chains that end at an administrative role.
- `lab/remediation.md` — how each finding is fixed in policy terms.
- `docs/paths.md` — walkthrough of the three planted escalation paths.
- `tests/test_detector.py` — tests that the detector finds the planted
  paths and does not flag the safe role.

## Run it

```bash
python3 lab/detector.py --data data/simulated_iam.json
python3 -m unittest discover -s tests -v
```

## What this lab does not do

- It does not connect to AWS, GCP, or any other cloud.
- It does not contain, use, or teach the handling of real credentials.
- It does not demonstrate an escalation against a real account. The
  paths it finds are planted in fictional data, and the report says so.

## Recent additions

- New patterns: a long multi-hop assume-role chain (`lab-junior -> lab-mid -> lab-senior -> lab-admin`) and wildcard policies (`iam:*`, `s3:*`), with detector coverage, remediation, and tests.
- `docs/attack-mapping.md` and `detections/sigma-rules.yml`: illustrative MITRE ATT&CK mapping and Sigma-style detection rules in lab log format.
