# The three planted paths

All names are fictional lab names. The detector output for each path
is reproduced in words here so the walkthrough can be followed
without running anything.

## Path 1 — Assumption chain to admin

`lab-developer` can assume `lab-deployer`, and `lab-deployer` can
assume `lab-admin`, which holds the administrator policy. Starting
from `lab-developer`, the detector reports the chain
`lab-developer -> lab-deployer -> lab-admin`.

Lesson: privilege is transitive through assumption. Reviewing a
single role's policies is not enough; review the chain.

## Path 2 — Privilege-granting policy

`lab-orphan` holds a policy with `iam:AttachUserPolicy` and
`iam:PutUserPolicy`. A holder of that role could attach a broader
policy to themselves. The detector flags the role and both actions.

Lesson: a role that can grant privileges is effectively an admin
role, whatever its name says.

## Path 3 — The safe role (negative control)

`lab-auditor` holds only a read-only policy and can assume nothing.
The detector reports no admin path and no privilege-granting action
for it. A detector that flags everything is useless; the safe role
exists to prove this one does not.
