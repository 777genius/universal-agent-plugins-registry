#!/usr/bin/env node
'use strict';

// Public, credential-free protocol evidence only. Never invokes a tool.
const assert = require('node:assert/strict');

const endpoint = 'https://mcp.firecrawl.dev/v2/mcp';
const headers = {
  Accept: 'application/json, text/event-stream',
  'Content-Type': 'application/json',
};

function parseResponse(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) return JSON.parse(trimmed);
  const messages = trimmed.split(/\r?\n/)
    .filter((line) => line.startsWith('data:'))
    .map((line) => JSON.parse(line.slice(5).trim()));
  assert(messages.length > 0, 'MCP response contained no JSON message');
  return messages.at(-1);
}

async function request(body, sessionId) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: sessionId ? { ...headers, 'Mcp-Session-Id': sessionId } : headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(response.status, 200, `Unexpected MCP HTTP status ${response.status}`);
  return {
    payload: parseResponse(await response.text()),
    sessionId: response.headers.get('mcp-session-id') || sessionId,
  };
}

async function main() {
  const initialized = await request({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'universal-agent-plugins-e2e', version: '1.0.0' },
    },
  });
  assert(initialized.payload.result?.serverInfo?.name, 'Missing MCP server identity');

  const listed = await request({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
    params: {},
  }, initialized.sessionId);
  const names = listed.payload.result?.tools?.map((tool) => tool.name).sort();
  assert.deepEqual(names, ['firecrawl_parse', 'firecrawl_scrape', 'firecrawl_search']);

  console.log(JSON.stringify({
    endpoint,
    protocolVersion: initialized.payload.result.protocolVersion,
    serverInfo: initialized.payload.result.serverInfo,
    toolCount: names.length,
    tools: names,
    scope: 'Credential-free initialize and tools/list only; no tool was invoked.',
  }));
}

main().catch((error) => {
  console.error(String(error.message).split('\n')[0]);
  process.exitCode = 1;
});
