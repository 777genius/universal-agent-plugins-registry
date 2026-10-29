# Agent Notifications

Desktop notifications for coding agents. Get a native alert the moment a task finishes, needs your input, or fails.

<!-- agentplugins-install:start -->
## Installation unavailable

> Installation is currently unavailable because the Directory has no eligible release target.
<!-- agentplugins-install:end -->

Agent Notifications is installed with its own release installer: the product ships a platform notifier binary that only its signed release archives carry, so the universal installer cannot materialize a working package. Use the [guided installer](https://agent-notifications.com/#install) from the product site.

This Directory entry exists so the product is listed and documented here; the universal installer deliberately refuses to install it. The component files in this package mirror the portable package published by [777genius/agent-notifications](https://github.com/777genius/agent-notifications) at commit `61a8775d996635e677073d3a643627171cfd4b94` and record the plugin's exact shape. The notifier binary itself is not included and is delivered only by the official installer.

- Component: MCP server (`agent-notifications`, stdio) and skill (`agent-notifications`)
- Vendor installer: https://agent-notifications.com/#install
- Source: https://github.com/777genius/agent-notifications
- License: GPL-3.0-or-later

Review the skill's guidance on when to notify before enabling it: notifications are user attention, not a logging channel.
