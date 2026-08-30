# Research notes

Trustline MCP builds on established, source-linked concepts rather than copying an existing product:

- [Model Context Protocol `2026-07-28` stdio binding](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio), [discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover), and [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) for the outer service framing, metadata, catalog, and result contract.
- The MIT-licensed [`@modelcontextprotocol/client` v2](https://github.com/modelcontextprotocol/typescript-sdk/tree/main/packages/client) is pinned as a development-only interoperability oracle. Trustline's shipped runtime does not import or copy its implementation.
- [JSON-RPC 2.0](https://www.jsonrpc.org/specification) for request and response shapes.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) as background for deterministic JSON. Trustline implements a documented small canonical subset; it does not claim full RFC 8785 conformance.
- [in-toto](https://github.com/in-toto/in-toto) and [DSSE](https://github.com/secure-systems-lab/dsse) as future provenance integration directions.
- Deny-overrides combining algorithms used by policy systems such as XACML. Trustline uses a small purpose-built model and does not claim XACML compatibility.

The research hypothesis is testable: an inspectable, default-deny tool policy plus tamper-evident transcripts can make local agent demos easier to audit. The repository does not claim that this alone makes an agent safe.
