# Windows protected-mode blocker

CATL has a read-only current-token AppContainer/restriction gate and a named-pipe DACL allowlist inspector (`catl.platform_proofs`). **This is not an AppContainer launcher or secure named-pipe server.** On Linux these checks refuse execution.

Before enabling Windows: create an independently reviewed restricted-token/AppContainer launch path with explicit no-capabilities policy, dedicated SID and named-pipe ACL, confirm all child processes inherit confinement, deny non-CATL paths, validate network and filesystem denial as an attacker UID, and execute tests on a real Windows kernel. Never use `subprocess.Popen()` with ordinary inherited access as a "protected" mode.
