# Trustline MCP offline simulation

Artifact: `trustline.report/v1`

- Policy: **offline-attack-lab**
- Policy digest: `1ef2a32bfb866993e019b91c5b28a9679c8f15ea5485de4fb55ddc21fe17898f`
- Allowed: **4**
- Denied: **5**
- Approval required: **1**
- Protocol errors: **1**
- Audit valid: **true**
- Audit root: `aaa061f7ca6c19146b507174bb1d035d16877ea5a84515e590fc89cc5543bf00`

| # | Decision | Reasons | Hash |
|---:|---|---|---|
| 0 | allow | path-allow, tool-allow | `105d2e519c56` |
| 1 | deny | path-traversal | `e7b94493f3d5` |
| 2 | allow | host-allow, tool-allow | `c91a98f10e58` |
| 3 | allow | host-allow, tool-allow | `b67e860c9ccb` |
| 4 | deny | quota-exceeded | `940320d06946` |
| 5 | deny | host-deny, host-unlisted, quota-exceeded | `cd2dcbe1941a` |
| 6 | approval | tool-approval | `2e1fade43341` |
| 7 | deny | argument-deny | `9239e9aeddf0` |
| 8 | allow | tool-approval | `6730f7d0286d` |
| 9 | default-deny | no-allow-rule | `cbb484f73de6` |
| 10 | protocol-error | - | `aaa061f7ca6c` |

> This is an offline JSON-RPC transcript simulator. It does not intercept production OAuth or HTTP traffic.
