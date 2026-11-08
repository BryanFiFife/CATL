# CATL Linux four-UID kernel preflight (v14)

This is a **standalone operating-system isolation fixture**, not CATL broker or Hermes acceptance. It uses real Linux AF_UNIX sockets, `SO_PEERCRED` and synthetic UIDs/GIDs. It does not create accounts, modify host configuration or open TCP ports.

Run **only in a disposable root-capable Linux VM/container** after reviewing the script:

```bash
CATL_DISPOSABLE_LINUX_TEST_HOST=YES python3 tools/linux_kernel_identity_matrix_v14.py
```

Without the explicit environment acknowledgement the script fails closed. It also refuses Python optimisation (which would discard `assert` checks) and refuses synthetic IDs that already belong to real host accounts/groups.

## Checks performed

- Agent UID can connect to agent IPC, operator UID can connect to operator IPC.
- Agent/operator cannot cross-connect; backend UID cannot connect to either privileged channel.
- Broker UID reads its private fake audit key, while agent, operator and backend UIDs cannot.
- Synthetic agent process receives the minimal environment rather than a canary secret present in its parent.

In the disposable test container, **11/11 checks passed**, and missing opt-in and `python -O` both failed closed. These tests establish kernel capability and safe harness setup only. They do not start CATL services or a real Hermes runtime, enforce a production systemd cgroup/LSM policy, verify external effects, attest hardware user presence, or replace an independent penetration test.

Public-production release remains **NO-GO** pending integrated native acceptance and the remaining release gates.
