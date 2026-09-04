# Cloudflare

Community package for Cloudflare's 13 platform skills and API MCP server.
The skills cover Workers, Durable Objects, Agents SDK, networking, email,
Sandbox, Turnstile, performance, and Wrangler.

<!-- agentplugins-install:start -->
## Install

```bash
npx universal-agent-plugins add cloudflare --target codex
```
<!-- agentplugins-install:end -->

Cloudflare API access requires authentication in your agent. Installation does
not sign you in, grant permissions, or execute the bundled scripts. Review the
skills and requested operations before allowing changes to a Cloudflare account.

For a focused MCP connection, use `cloudflare-docs`, `cloudflare-bindings`,
`cloudflare-observability`, or `cloudflare-radar` instead. These are separate
packages, not prerequisites for this one.

## Source and compatibility

This community bridge is built from [cloudflare/skills](https://github.com/cloudflare/skills)
at commit `9177f9a0bafc1ab61a0dae8dca57a8eb4d9f636d`. It preserves all 13 skills,
their supporting files and executable permissions, and the original API MCP
configuration. The `cloudflare` and `turnstile-spin` skill reference lists are
moved from unsupported YAML frontmatter into Markdown links; no guidance or
reference files are removed. See [NOTICE](NOTICE) and [LICENSE](LICENSE).

The bridge is independently packaged by 777genius and is not published or
endorsed by Cloudflare. Existing installations of the older MCP-only community
distribution keep their source until the user explicitly switches distributions.
