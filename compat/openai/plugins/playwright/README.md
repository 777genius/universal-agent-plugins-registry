# Playwright

Community package for Playwright MCP. Automate browsers and inspect web pages through Playwright.

<!-- agentplugins-install:start -->
## Install

```bash
npx universal-agent-plugins add playwright --target codex
```
<!-- agentplugins-install:end -->

This package is independently assembled by 777genius from configuration anchored to microsoft/playwright-mcp at commit `8a13ef8e9f7385a0f89477922127f31cbfde9761`. It is not authored, published, or endorsed by Microsoft.

- Component: MCP server
- Transport: `stdio`
- Runtime: integrity-locked `@playwright/mcp@0.0.80`; install scripts are disabled
- Requirement: Node.js 22 or newer; the first launch downloads the locked npm closure into plugin data
- Upstream source: https://github.com/microsoft/playwright-mcp
- Authentication: No credential is declared by this package.

Playwright MCP can navigate pages and perform browser actions. Review every requested action before enabling it in a sensitive session.
