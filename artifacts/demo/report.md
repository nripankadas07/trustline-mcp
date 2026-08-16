# Trustline MCP offline simulation

Artifact: `trustline.report/v1`

- Policy: **offline-attack-lab**
- Policy digest: `4280a64242747a4a2f33c12fdf3dcf832c37dcb200612ad48a8f4e18049900a3`
- Allowed: **4**
- Denied: **5**
- Approval required: **1**
- Protocol errors: **1**
- Audit valid: **true**
- Audit root: `b690877bf824a4dcf7bbab483a4f240fbc4deaead13a8c6bd3a4a2c3bd6bf9c9`

| # | Decision | Reasons | Hash |
|---:|---|---|---|
| 0 | allow | path-allow, tool-allow | `b40231c9b3ea` |
| 1 | deny | path-traversal | `fbe434396b98` |
| 2 | allow | host-allow, tool-allow | `2c0fb0c3eb0c` |
| 3 | allow | host-allow, tool-allow | `d2f36cba78b4` |
| 4 | deny | quota-exceeded | `eb1e42042b43` |
| 5 | deny | host-deny, host-unlisted, quota-exceeded | `a4a46297f130` |
| 6 | approval | tool-approval | `34472c6ea929` |
| 7 | deny | argument-deny | `2979e930db44` |
| 8 | allow | tool-approval | `4f2e6c5a7623` |
| 9 | default-deny | no-allow-rule | `9ee084ae9a89` |
| 10 | protocol-error | - | `b690877bf824` |

> This is an offline JSON-RPC transcript simulator. It does not intercept production OAuth or HTTP traffic.
