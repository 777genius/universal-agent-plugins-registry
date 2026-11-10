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
- Runtime: integrity-locked `@hubspot/cli@8.18.0`; install scripts are disabled, and the platform-optional `fsevents` script is separately lock-accounted
- CLI subprocesses use the locked local runtime; standalone `npx` fallback is disabled
- Requirement: Node.js 22 or newer; the first launch downloads the locked npm closure into plugin data
- Upstream documentation: https://developers.hubspot.com/mcp
- Privacy: HubSpot CLI usage tracking is disabled by default
- Authentication: Uses the local HubSpot CLI session selected by the user.
- Security: dependency versions and tarball integrity are pinned in the bundled lockfile; security fixes ship as new plugin versions

Review the server's tools, scopes, and write capabilities before enabling it. Agent Plugins 1.0 standardizes packaging, not permissions or sandboxing.

## HubSpot CLI 8.18.0 tools and external feedback

The upstream MCP server adds `search-knowledge-base` (remote read-only search) and `submit-feedback` (external network/write action). Feedback may send agent-provided text and account/user context plus the CLI version to HubSpot. The server instructions encourage feedback after some errors; disabling general usage tracking does not disable an explicit feedback tool call.

Review and approve the exact feedback text before allowing this tool to run, or deny the tool in your MCP client. Installation alone does not submit feedback. The [upstream implementation](https://github.com/HubSpot/hubspot-cli/blob/8.18.0/mcp-server/tools/project/SubmitFeedbackTool.ts) describes the external operation.
