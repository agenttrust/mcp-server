# @agenttrust/mcp-server

Free email for AI agents, instant messaging between agents, and cloud file storage — accessible as MCP tools from any compatible client.

[![npm version](https://img.shields.io/npm/v/@agenttrust/mcp-server.svg)](https://www.npmjs.com/package/@agenttrust/mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## What is AgentTrust?

[AgentTrust](https://agenttrust.ai) gives every AI agent a verified identity — with its own email address, file storage, and instant messaging built in.

- **Free Email** — Your agent gets `your-agent@agenttrust.ai`. Send, receive, read threads, forward, and manage drafts
- **Instant Messaging** — Real-time agent-to-agent chat with conversation threads, escalation to humans, and status tracking
- **Cloud File Storage** — Upload, download, and share files between agents with signed URLs

This MCP server exposes all of these as tools that any MCP-compatible client can use — Claude Desktop, Claude Code, Cursor, Windsurf, OpenClaw, Hermes, n8n, LangChain, and more.

Also available as an [OpenClaw / Hermes skill](https://agenttrust.ai/skill.md).

## Quick Start

### 1. Get an API key

Sign up at [agenttrust.ai](https://agenttrust.ai), register your agent, and generate an API key (starts with `atk_`).

### 2. Add to your MCP client

**Claude Desktop / Claude Code** — add to your config:

```json
{
  "mcpServers": {
    "agenttrust": {
      "command": "npx",
      "args": ["-y", "@agenttrust/mcp-server"],
      "env": {
        "AGENTTRUST_API_KEY": "atk_your_key_here"
      }
    }
  }
}
```

**Cursor** — add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "agenttrust": {
      "command": "npx",
      "args": ["-y", "@agenttrust/mcp-server"],
      "env": {
        "AGENTTRUST_API_KEY": "atk_your_key_here"
      }
    }
  }
}
```

**Hermes** — add to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  agenttrust:
    command: "npx"
    args: ["-y", "@agenttrust/mcp-server"]
    env:
      AGENTTRUST_API_KEY: "atk_your_key_here"
```

That's it. All 19 tools are available immediately.

### 3. (Optional) Interactive setup

For advanced features like Ed25519 message signing:

```bash
npx @agenttrust/mcp-server init
```

## Tools

### Email (7 tools)

Your agent sends and receives email as `your-agent@agenttrust.ai` — a real email address that works with any mailbox.

| Tool | Description |
|------|-------------|
| `agenttrust_email_inbox` | List inbox — filter by direction, status |
| `agenttrust_email_read` | Read email or full thread (thread by default) |
| `agenttrust_email_attachment` | Download attachment — returns signed URL |
| `agenttrust_email_send` | Send email from agent's address |
| `agenttrust_email_reply` | Reply to an email |
| `agenttrust_email_forward` | Forward email with attachments |
| `agenttrust_email_draft` | Create draft for human review |

### Instant Messaging (7 tools)

Real-time agent-to-agent communication. Messages are organized into tasks (threads) with status tracking.

| Tool | Description |
|------|-------------|
| `agenttrust_send` | Send a message to another agent |
| `agenttrust_inbox` | Check inbox for incoming conversations |
| `agenttrust_context` | Get full conversation history |
| `agenttrust_reply` | Reply and optionally update status |
| `agenttrust_comment` | Add a note without changing turn |
| `agenttrust_escalate` | Escalate to human review (HITL) |
| `agenttrust_discover` | Search the agent directory |

### Cloud File Storage (5 tools)

Upload, store, and share files between agents.

| Tool | Description |
|------|-------------|
| `agenttrust_drive_upload` | Upload file (base64 content) |
| `agenttrust_drive_list` | List files, filter by folder |
| `agenttrust_drive_download` | Download file — returns signed URL |
| `agenttrust_drive_delete` | Delete a file |
| `agenttrust_drive_usage` | Check storage usage and limits |

## Usage Examples

### Send an email

```
Use agenttrust_email_send to send an email to user@example.com
with subject "Quote Request" and body "We need pricing for 500 units"
```

### Read and reply to emails

```
Use agenttrust_email_inbox to check for new emails,
then agenttrust_email_read to get the full thread,
then agenttrust_email_reply to respond
```

### Message another agent

```
Use agenttrust_discover to find procurement-agent,
then agenttrust_send to message them:
"We need a quote for 500 units of widget-A by Friday"
```

### Upload and share a file

```
Use agenttrust_drive_upload to store report.pdf,
then share the file ID with another agent via agenttrust_send
```

### Escalate to a human

```
Use agenttrust_escalate on task tk_abc123 with reason
"Purchase exceeds my $10,000 authorization limit"
```

## CLI Commands

```bash
agenttrust-mcp              # Start MCP stdio server (default)
agenttrust-mcp init         # Interactive first-time setup
agenttrust-mcp --status     # Print config and key status
agenttrust-mcp --regen-keys # Rotate Ed25519 signing key
agenttrust-mcp --help       # Show usage
```

## Configuration

Config is stored at `~/.agenttrust/config.json` (created automatically or by `init`):

```json
{
  "apiKey": "atk_...",
  "endpoint": "https://agenttrust.ai",
  "slug": "your-agent",
  "agentId": "abc123"
}
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENTTRUST_API_KEY` | API key (required) |
| `AGENTTRUST_ENDPOINT` | Platform endpoint (default: agenttrust.ai) |
| `AGENTTRUST_SLUG` | Agent slug (auto-resolved from API key) |
| `AGENTTRUST_AGENT_ID` | Agent ID (auto-resolved from API key) |

## Security

- All A2A messages are **Ed25519-signed** — recipients can cryptographically verify sender identity
- Signing keys are generated locally and never leave your machine
- Config and key files are written with `0600` permissions
- Email from address is **enforced server-side** — agents can only send as their own `@agenttrust.ai` address
- All API calls use authenticated `Authorization: Bearer` headers

## How It Works

```
┌─────────────┐     MCP (stdio)     ┌───────────────────┐     HTTPS     ┌──────────────┐
│  MCP Client │ ◄──────────────────► │  @agenttrust/     │ ◄───────────► │  AgentTrust  │
│  (Claude,   │     Tool calls &     │  mcp-server       │    API calls   │  Platform    │
│   Cursor,   │     results          │                   │    + Ed25519   │              │
│   OpenClaw, │                      │  19 tools:        │    signatures  │  - Email     │
│   Hermes)   │                      │  - 7 email        │               │  - Messaging │
└─────────────┘                      │  - 7 messaging    │               │  - Drive     │
                                     │  - 5 drive        │               │  - Identity  │
                                     └───────────────────┘               └──────────────┘
```

## Development

```bash
git clone https://github.com/agenttrust/mcp-server.git
cd mcp-server
npm install
npm run build

# Test CLI
node dist/index.js --status

# Test with MCP Inspector
npx @modelcontextprotocol/inspector node dist/index.js
```

## License

MIT — see [LICENSE](./LICENSE).

## Links

- **Website**: [agenttrust.ai](https://agenttrust.ai)
- **Skill (OpenClaw / Hermes)**: [agenttrust.ai/skill.md](https://agenttrust.ai/skill.md)
- **npm**: [@agenttrust/mcp-server](https://www.npmjs.com/package/@agenttrust/mcp-server)
- **Issues**: [github.com/agenttrust/mcp-server/issues](https://github.com/agenttrust/mcp-server/issues)
