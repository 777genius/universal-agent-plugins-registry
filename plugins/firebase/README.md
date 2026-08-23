# Firebase

Google Firebase MCP integration. Manage Firestore databases, authentication, cloud functions, hosting, and storage. Build and manage your Firebase backend directly from your development workflow.

<!-- agentplugins-install:start -->
## Installation unavailable

> Installation is currently unavailable because the Directory has no eligible release target.
<!-- agentplugins-install:end -->

This is an independent community package for [Agent Plugins 1.0](https://agent-plugins.org/specification). It is not an endorsement or an official package from Firebase.

- Component: MCP server
- Transport: `stdio`
- Runtime: integrity-locked `firebase-tools@15.28.1`; install scripts are disabled
- Requirement: Node.js 22 or newer; the first launch downloads the locked npm closure into plugin data
- Upstream documentation: https://firebase.google.com
- Privacy: Firebase CLI usage analytics remain disabled unless the user explicitly opted in through their Firebase CLI configuration
- Authentication: Uses the local Firebase CLI session and active project selected by the user.

Review the server's tools, scopes, and write capabilities before enabling it. Agent Plugins 1.0 standardizes packaging, not permissions or sandboxing.
