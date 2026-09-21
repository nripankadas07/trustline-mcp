# Security policy

Trustline MCP is a simulator and must not be treated as a production security boundary.

`serve-http` is deliberately bound to `127.0.0.1` and accepts only loopback
browser origins. It does not authenticate callers: other processes running as
the same user or on the same host can still reach the listener. Do not expose
it through a reverse proxy, port forward, container publish flag, or public
interface without adding and independently reviewing transport security and
authorization.

Report vulnerabilities privately to the repository owner through GitHub Security Advisories. Include the affected version, a minimal transcript/policy, expected behavior, and observed behavior. Do not include live credentials.

Supported line: `0.1.x`. There is no guaranteed response SLA for this independent project.
