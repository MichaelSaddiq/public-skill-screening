# Public skill screening with NVIDIA SkillSpector

Small remote integration for screening public third-party skill candidates before
considering their ideas. NVIDIA SkillSpector 2.11.2 does the analysis; this adapter
only restricts inputs, contains execution and projects a minimal report.

Manual GitHub Actions only. Standard Ubuntu hosted runner, no paid LLM, no cache
or artifact uploads. Candidate files stay on the disposable remote runner.
Public repository code, candidate URLs, workflow activity and sanitized results
are public. Never submit private repositories, secrets, internal skills or files.

The scanner image pins NVIDIA's commit, its frozen dependency lock, and the
Python base image. Debian installation packages and the hosted runner OS remain
provider-maintained dependencies. NVIDIA's scanner and its dependencies are
trusted software, not independently proved malware-free.

Anonymous candidate fetching occurs inside an unprivileged, resource-limited
container. Analysis runs separately with no network, no secrets, no writable
candidate mount, no Docker socket, and no host/private-directory mounts. The
candidate's scripts are never intentionally executed or installed. Container or
scanner vulnerabilities remain possible; this is not zero-risk clearance.

Static-only, offline mode: no semantic LLM analysis, no live OSV vulnerability
lookup, and no following external references. The report must not imply those
checks ran. Any finding or CAUTION/DO_NOT_INSTALL means REJECTED. Missing,
incomplete or failed scans mean UNVERIFIED. Only a complete, no-finding static
result is ELIGIBLE_FOR_INSPIRATION_REVIEW, never permission to install or execute.
Unknown injection can evade static rules; subsequent review remains untrusted.

Use a repository URL, or a tree URL for its current default branch or current
HEAD commit. Other refs are rejected, not silently substituted. A tree scan only
covers the selected subtree, not dependencies or other parts of its repository.
Record the actual candidate commit and source digest in the result.

The default workflow mode checks NVIDIA's own public benign/malicious fixtures.
No customer or internal material is used for scanner testing. This repository is
the remote screening integration project; runs test candidate suitability for
that integration, not a general-purpose hosted-compute service.
