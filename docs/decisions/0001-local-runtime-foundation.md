# ADR 0001: Local runtime foundation

Status: accepted for this assignment, 2026-10-17.

Context: the existing Aegis checkout is already a Git repository with no application
code. The eventual project has separate runtime and SBUnix repositories.

Decision: use this root as aegis-runtime, not a nested Git/module directory. Use
neutral module path aegis.local/runtime, Go 1.26 and standard libraries. Retain
.gitattributes and existing history. Reserve future directories with README files,
not code stubs. Use MIT provisionally and review before publication. Keep runtime
data and credentials outside the repository and ignored defensively.

Alternatives: nested aegis-runtime (unnecessary nesting); guessed GitHub namespace
(false ownership assumption); external dependencies (not needed for this slice).

Consequences: imports will change once a real module namespace is chosen. Directory
names do not imply features exist. No pushes, remotes, commits or kernel changes
are required by this assignment.
