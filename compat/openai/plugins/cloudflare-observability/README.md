# Cloudflare Observability

Community package for Cloudflare Observability MCP. Query Workers logs and analytics through Cloudflare's hosted Observability MCP server.

<!-- agentplugins-install:start -->
## Install

```bash
npx universal-agent-plugins add cloudflare-observability --target codex
```
<!-- agentplugins-install:end -->

Cloudflare authentication is completed in your agent. Installation does not
sign you in or grant account access. Review the server's tools and requested
permissions before enabling operations.

The hosted server is implemented in
[cloudflare/mcp-server-cloudflare/apps/workers-observability](https://github.com/cloudflare/mcp-server-cloudflare/tree/main/apps/workers-observability).
This community bridge pins its configuration evidence to commit
`db9084730dd45ebb6ac4dd5d3181d189cc96e98d`; no server source is bundled or run
during installation. The remote service itself is operated and updated by
Cloudflare. See [NOTICE](NOTICE) for attribution.

The package is independently assembled by 777genius and is not authored,
published, or endorsed as a distribution by Cloudflare.
