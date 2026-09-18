# TinyFish

Community package for TinyFish MCP. Search the live web, fetch clean page content, and run browser automations through TinyFish's hosted server.

<!-- agentplugins-install:start -->
## Install

```bash
npx universal-agent-plugins add tinyfish --target codex
```
<!-- agentplugins-install:end -->

This package is independently assembled by 777genius from configuration anchored to tinyfish-io/tinyfish-cookbook at commit `8615317f6db58ae776dd53817ac30668c1db5ef8`. It is not authored, published, or endorsed by TinyFish.

- Component: MCP server
- Transport: `streamable-http`
- Endpoint: `https://agent.tinyfish.ai/mcp`
- Upstream source: https://github.com/tinyfish-io/tinyfish-cookbook
- Authentication: TinyFish manages OAuth for the hosted endpoint; no credential is embedded in this package.

Review the server's tools, scopes, and write capabilities before enabling it. Agent Plugins 1.0 standardizes packaging, not permissions or sandboxing.
