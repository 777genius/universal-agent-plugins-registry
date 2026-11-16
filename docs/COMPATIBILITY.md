# Compatibility and authentication

All packages target Agent Plugins 1.0.0. Schema validation proves package
conformance; it does not prove that a vendor endpoint is available, that OAuth
will succeed in every client, or that every client exposes the same tools.

The standard-compatible launch clients and supported transports are maintained
at [agent-plugins.org](https://agent-plugins.org/compatible-clients).

Directory compatibility is release- and environment-specific. The website
shows one product card even when upstream and community distributions coexist,
labels the reviewed **Default source**, and links alternatives and immutable
provenance. Existing installs stay on their recorded distribution during
update; changing source is an explicit `switch`.

## Pi target and Directory status

The published installer 0.1.102 supports Pi Skills, stdio and Streamable HTTP MCP
(and native extensions) for user and project profiles. It does **not** imply
that a signed Directory release is already authorized for Pi. The current
reviewed Directory has **37 active release policies and none names Pi**.
These policies predate Pi's component support. A package with eligible Skills/MCP
is a *candidate* for Pi qualification, not a proven signed installation.
A read-only audit of all 37 active-policy source manifests found 29 eligible
Streamable HTTP MCP distributions, six stdio MCP distributions, one
Skills-component distribution and one suspended stdio distribution (excluded).
This classifies transports, **not** login or tool execution.

**Marketing Kit is not a dependency-free Skills install:** although its own
release lists only Skills, its required `uap.toml` dependencies include Notion,
HubSpot CRM and Playwright Bridge. With no signed Pi authorization for HubSpot
CRM, the published 0.1.102 saved-source planner refuses Marketing Kit for
both `user` and `project`; it must not be labelled Pi-installable merely
because its Skills files can be planned independently. On each of Linux, macOS
and Windows, the [exact-head E2E run](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/42732521352)
passed six native Pi lifecycle cases and planned 70 of 72 eligible source/scope
cases; the two genuine dependency refusals are not PASS. A successful
direct-source project dry-run is not itself a signed project-scope grant.

For source-bound validation without silently broadening signed authority, first
run an exact Git revision with `--dry-run` on a disposable Pi profile:

```sh
npx -y universal-agent-plugins@0.1.102 add github:upstash/context7@769c6cd22c3d95462d1f55d789e9532cabefa5a9//plugins/agent-plugins/context7 --target pi --scope user --dry-run
```

The same package's signed `context7` alias **does not yet authorize Pi**; a
direct Git selector is a separate, explicit trust path and must be checked by
the CLI. Do not conflate staged configuration, approved project trust, endpoint
login, MCP tool execution, or a live provider account. See the
[Pi Directory rollout qualification plan](../docs/plans/2026-11-09-pi-directory-global-qualification.md).

## Package matrix

| Plugin | Component | Authentication and scope |
| --- | --- | --- |
| `agent-code-navigator` | 4 skills | Local tools only; specialized tools are optional |
| `atlassian` | Streamable HTTP | Client-managed Atlassian OAuth |
| `chrome-devtools` | stdio | Local browser session; pinned npm package |
| `cloudflare` | Streamable HTTP | Client-managed Cloudflare authorization |
| `cloudflare-bindings` | Streamable HTTP | Client-managed Cloudflare authorization |
| `cloudflare-docs` | Streamable HTTP | Public documentation endpoint |
| `cloudflare-observability` | Streamable HTTP | Client-managed Cloudflare authorization |
| `cloudflare-radar` | Streamable HTTP | Public telemetry behind client-managed Cloudflare OAuth |
| `context7` | stdio | No credential stored; service limits may apply |
| `docker-hub` | stdio | Public data only in portable config; authenticated writes need client-specific secrets |
| `figma` | Streamable HTTP | Client-managed Figma OAuth |
| `firebase` | stdio | Uses the local Firebase CLI login and selected project |
| `firecrawl` | Streamable HTTP | Public keyless endpoint; service limits may apply |
| `github` | Streamable HTTP | Client-managed auth; no PAT stored |
| `gitlab` | Streamable HTTP | Client-managed GitLab OAuth |
| `greptile` | Streamable HTTP | Client-managed auth; no API key stored |
| `heroku` | Streamable HTTP | Client-managed Heroku OAuth |
| `hubspot-crm` | Streamable HTTP | Client-managed OAuth; upstream may remain beta/read-only |
| `hubspot-developer` | stdio | Uses the local HubSpot CLI login |
| `linear` | Streamable HTTP | Client-managed Linear OAuth |
| `neon` | Streamable HTTP | Client-managed Neon OAuth |
| `notion` | Streamable HTTP | Client-managed Notion OAuth |
| `playwright` | stdio | Local browser session; integrity-locked npm package |
| `sentry` | Streamable HTTP | Client-managed Sentry OAuth |
| `statsig` | Streamable HTTP | Client-managed Statsig authorization |
| `stripe` | Streamable HTTP | Client-managed Stripe OAuth; may expose write tools |
| `supabase` | Streamable HTTP | Client-managed auth and project scoping; development/test data only per upstream guidance |
| `tinyfish` | Streamable HTTP | Client-managed TinyFish OAuth |
| `vercel` | Streamable HTTP | Client-managed Vercel OAuth |

## OpenAI delivery boundary

| Package group | Count | Codex | ChatGPT |
| --- | ---: | --- | --- |
| stdio MCP | 6 | Generated `.mcp.json` package | Not supported; Codex-only |
| Streamable HTTP MCP | 22 | Generated `.mcp.json` package | Requires a registered `.app.json` binding |
| Skills-only | 1 | Generated skills package | Separate skills package; package UI E2E not claimed |

Cloudflare Docs is the only remote package with a registered ChatGPT
development binding. Its direct no-auth connection passed `list_resources` and
one read-only documentation search. Its registered personal app also passed
Plugins UI discovery, user-attested manual activation, and the same read-only
runtime. Separate evidence proves repository marketplace ingestion, official
manager installation, cache materialization, and exact `.app.json` linkage. It
does not yet prove ChatGPT Work UI activation or package-routed runtime. No other
remote package is claimed as ChatGPT-installable. The website keeps ChatGPT
visible but disabled for those releases and explains that a registered app
binding is required.

## Dependency pins

Context7 community, Firebase, and HubSpot Developer security closures were
refreshed on 2026-10-29. The other pins retain their 2026-09-06 verification
record. All listed npm pins are stable releases:

| Runtime dependency | Pin |
| --- | --- |
| `chrome-devtools-mcp` | `1.8.0` |
| `@playwright/mcp` | `0.0.80` |
| `@upstash/context7-mcp` | `4.4.4` |
| `firebase-tools` | `15.35.0` |
| `@hubspot/cli` | `8.18.0` |
| `mcp/dockerhub` | OCI digest `sha256:76454af…d4248` |

The exact current closures are bound to the
[runtime qualification record](runtime-security-qualification.md) and its
Linux, macOS, and Windows checks. The dated [verification record](VERIFICATION.md)
separates historical runtime evidence from current source and advisory audits.
Credential-free qualification does not prove client activation or authenticated
provider operations.
The Context7 pin is for `777genius/context7`; the `upstash/context7` default
distribution is unchanged.

The code-intelligence skills document current optional versions of Semble
`0.5.4`, CodeGraphContext `0.5.6`, and Serena `1.6.1`.

## Verification levels

- `Schema`: `plugin.json`, `mcp.json`, skills, path rules, and pins validate.
- `Reachability`: the endpoint or package exists without authenticating.
- `Authenticated`: a user completed the vendor flow in a specific client.
- `Behavior`: representative read and write operations were tested safely.

Runtime and authentication claims are tracked with a client, date, account
scope, and exact scenario in [the test matrix](TEST_MATRIX.md).
