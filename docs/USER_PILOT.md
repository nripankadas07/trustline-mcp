# Try Trustline MCP and tell us what breaks

For MCP developers and reviewers of agent tool permissions. Pick the browser route or a local task below; stopping at a
blocker is useful feedback. The times are estimates, not a completion requirement.

[Give first-use feedback](https://github.com/nripankadas07/trustline-mcp/issues/new?template=user_feedback.yml) ·
[See known limitations](LIMITATIONS.md)

## Try it in your browser (about 5 minutes)

Open the [synthetic report](https://nripankadas07.github.io/trustline-mcp/).
Find one allowed call, one denied call, and one call requiring approval. Explain
which rule produced each decision. Could you tell what to change if a decision
was wrong? Report the first confusing point; no installation is needed.

## Run a policy experiment (about 15 minutes)

Requires Git and Node.js 22 or newer. From a terminal:

```bash
git clone https://github.com/nripankadas07/trustline-mcp.git
cd trustline-mcp
npm ci
npm run build
node dist/src/cli.js simulate fixtures/policy.json fixtures/attack-transcript.txt pilot/baseline
node dist/src/cli.js verify pilot/baseline/audit.json
```

Open `pilot/baseline/index.html` in your browser. Copy `fixtures/policy.json` to
`pilot-policy.json`; change the `search-quota` limit from `2` to `1`. Before
running again, predict which search call will change from allow to deny:

```bash
node dist/src/cli.js simulate pilot-policy.json fixtures/attack-transcript.txt pilot/changed
node dist/src/cli.js verify pilot/changed/audit.json
```

Compare the reports. Did your prediction match the decision and reason?
The final malformed transcript line is intentional and should remain a
protocol error. A useful report includes the rule ID, call ID, expected decision,
actual decision, and the explanation you needed.

## Test a question from your own work

Create a small **synthetic** transcript representing a permission question you
actually face (for example, two overlapping quotas or a path restriction).
State your expected decisions before running it. Keep all credentials,
proprietary tool arguments, internal paths, and private policies out of this
repository and public feedback. This is a simulator; it never executes upstream
tools. Approval identities are unauthenticated fixture data, and audit verification
checks unsigned bundle consistency. Read [limitations](LIMITATIONS.md).

## Share a specific observation

Use the [feedback form](https://github.com/nripankadas07/trustline-mcp/issues/new?template=user_feedback.yml). It asks for your task, route, outcome,
version, and one specific result or blocker. Browser reviews and bundled-fixture
runs help test usability; applying a relevant question from your own work gives
stronger evidence of usefulness. A claim that you would return is different from
actually returning: if you try it again, add a dated comment to the same issue
with the new task and result.

**Feedback is public.** Do not post secrets, personal records, private customer
or employer data, or raw private event ledgers. Quotes need your separate approval.
Security concerns belong in the repository's security-reporting path, not this
public form. No reward, star, or endorsement is required.
