# Firecrawl

Community package for Firecrawl MCP. Search, scrape, and parse public web content through Firecrawl's hosted server.

<!-- agentplugins-install:start -->
## Install

```bash
npx universal-agent-plugins add firecrawl --target codex
```
<!-- agentplugins-install:end -->

The keyless endpoint exposes Firecrawl's search, scrape, and parse tools with free usage limits. Advanced tools require Firecrawl authentication and are not declared by this package.

This package is independently assembled by 777genius from configuration anchored to firecrawl/firecrawl-mcp-server at commit `518e9299817aca118f0b3f5dded4c5fe7889d24e`. It is not authored, published, or endorsed by Firecrawl.

- Component: MCP server
- Transport: `streamable-http`
- Endpoint: `https://mcp.firecrawl.dev/v2/mcp`
- Upstream source: https://github.com/firecrawl/firecrawl-mcp-server
- Authentication: No credential is required by the keyless endpoint.

Review the server's tools, scopes, and write capabilities before enabling it. Agent Plugins 1.0 standardizes packaging, not permissions or sandboxing.
