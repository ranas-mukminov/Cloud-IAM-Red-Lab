# MITRE ATT&CK mapping — Cloud-IAM-Red-Lab (illustrative, lab only)

This mapping is an exercise aid for the simulated lab data. It is
not a formal ATT&CK assessment and makes no claim about any real
cloud account.

| Pattern | Mapping (illustrative) | Detection idea |
|---------|------------------------|----------------|
| Assumption chain to admin | T1078 Valid Accounts — a valid role used to assume a more privileged role, repeatedly | CloudTrail AssumeRole events forming a chain to an admin role |
| Privilege-granting policy | T1098 Account Manipulation (tactic family) — attaching a broader policy to oneself | AttachUserPolicy / PutUserPolicy events |
| Long multi-hop chain | T1078 Valid Accounts — transitive privilege through several hops | AssumeRole chains of length 4+ in the same session window |
| Wildcard policy | T1098 Account Manipulation / T1078 — a wildcard grant treated as admin-equivalent | Policy documents containing `*` actions, especially `iam:*` |

See `detections/sigma-rules.yml` for Sigma-style rules in lab
CloudTrail-like log format. They are detection format examples
only; no live telemetry claim is made for them.
