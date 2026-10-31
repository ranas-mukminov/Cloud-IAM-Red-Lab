# Remediation guidance (policy terms)

These fixes apply to the fictional lab data. In a real account, every
change goes through the account owner's change process, with a test in
a sandbox first.

## 1. Break the chain to admin

The lab chain is `lab-developer -> lab-deployer -> lab-admin`.
Fix it by removing one link, not by hoping nobody notices it:

- Remove `lab-admin` from `lab-deployer's` assumable roles, or
- Restrict `lab-deployer's` trust so only a named, audited principal
  can assume it, with MFA required, or
- Remove the administrator policy from `lab-admin` and replace it
  with the smallest set of actions that role actually needs.

After the fix, re-run the detector: the admin path must be gone, and
the test `test_no_admin_path_from_auditor` is the model for that check.

## 2. Remove privilege-granting actions

`lab-orphan` holds `iam:AttachUserPolicy` and `iam:PutUserPolicy`.
Those actions let a holder grant themselves more access, which makes
every other restriction on that role meaningless. Fix: remove both
actions, and grant policy changes only through a separate, audited
administrative process — never as a standing permission on a
working role.

## 3. Least privilege, checked regularly

- Every role gets the actions it demonstrably used in the last
  review period, and nothing else.
- Trust policies name specific principals, not broad groups.
- Assumption chains are reviewed whenever a role or policy changes,
  because a single new `can_assume` link can create a path to admin
  that no individual policy review would catch.

## 4. Detection, not just prevention

Keep a detector like this one in regular use: on every policy change,
and on a schedule. A path that appears after a change is a finding
about the change, and it is cheaper to fix before the change ships
than after.
