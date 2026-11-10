# HubSpot Developer

HubSpot Developer MCP integration for project scaffolding, CMS, builds, logs, and app workflows via the HubSpot CLI.

<!-- agentplugins-install:start -->
## Install

```bash
npx universal-agent-plugins add hubspot-developer --target codex
```
<!-- agentplugins-install:end -->

This is an independent community package for [Agent Plugins 1.0](https://agent-plugins.org/specification). It is not an endorsement or an official package from HubSpot Developer.

- Component: MCP server
- Transport: `stdio`
- Runtime: integrity-locked `@hubspot/cli@8.15.0`; install scripts are disabled, and the platform-optional `fsevents` script is separately lock-accounted
- CLI subprocesses use the locked local runtime; standalone `npx` fallback is disabled
- Requirement: Node.js 22 or newer; the first launch downloads the locked npm closure into plugin data
- Upstream documentation: https://developers.hubspot.com/mcp
- Privacy: HubSpot CLI usage tracking is disabled by default
- Authentication: Uses the local HubSpot CLI session selected by the user.
- Security: dependency versions and tarball integrity are pinned in the bundled lockfile; security fixes ship as new plugin versions

## Upstream HubSpot MCP feedback tool

HubSpot CLI **8.18.0** adds `search-knowledge-base` (remote, read-only search) and
`submit-feedback` (external write/network request). The feedback tool sends
agent-provided text to HubSpot and may associate it with the selected HubSpot
account/user identifiers and CLI version. The upstream MCP server instructions
encourage agents to use this tool after errors or confusing results; disabling
ordinary CLI usage tracking does **not** disable feedback submitted through
this tool. Credential filtering is not a substitute for reviewing the text.

Before allowing `submit-feedback`, review the intended message and approve the
external transfer in your MCP client. Configure per-tool confirmation or deny
this tool if your client supports those controls. Installing this plugin does
not itself submit feedback. See the [upstream tool implementation](https://github.com/HubSpot/hubspot-cli/blob/8.18.0/mcp-server/tools/project/SubmitFeedbackTool.ts)
and [HubSpot CLI 8.18.0 release notes](https://github.com/HubSpot/hubspot-cli/releases/tag/8.18.0).

The runtime package version listed above is the currently published plugin's
pin; an upgrade to 8.18.0 remains subject to separately verified dependency,
MCP-tool-surface, and release qualification.

Review the server's tools, scopes, and write capabilities before enabling it. Agent Plugins 1.0 standardizes packaging, not permissions or sandboxing.
