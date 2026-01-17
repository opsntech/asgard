# SSH Session Monitor - Central Server

A centralized SSH session monitoring system with real-time dashboard, Slack alerts, and multi-environment support.

## Features

- **Real-time Dashboard** - View active sessions across all environments
- **Session History** - Search and filter historical session data with CSV export
- **Server Monitoring** - Track server health and online status
- **Slack Alerts** - Configurable notifications for login/logout events
- **Multi-Environment** - Support for production, staging, dev, QA, etc.
- **REST API** - Full API for custom integrations and SIEM

## Quick Start

### 1. Deploy Central Server

```bash
# Clone the repository
git clone git@github.com:opsntech/infra-monitor.git
cd infra-monitor

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start with Docker
docker-compose up -d
```

### 2. Access Dashboard

Open http://localhost:5000 in your browser.

### 3. Deploy Agents

Use the Ansible role in `ansible/ssh-session-monitor` to deploy agents to your servers:

```bash
ansible-playbook -i inventory/ ssh-session-monitor-playbook.yml --ask-vault-pass
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_PASSWORD` | PostgreSQL password | (required) |
| `SECRET_KEY` | Flask secret key | (required) |
| `API_KEY` | API key for agent authentication | (required) |
| `SLACK_WEBHOOK` | Global Slack webhook URL | (optional) |

### Ansible Variables

| Variable | Description |
|----------|-------------|
| `ssh_alert_central_mode` | Enable central server mode |
| `ssh_alert_central_url` | Central server URL |
| `ssh_alert_api_key` | API key for authentication |
| `ssh_alert_environment` | Environment name (production, staging, etc.) |

## API Endpoints

### Dashboard Data

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/stats` | GET | Dashboard statistics |
| `/api/v1/sessions` | GET | List sessions with filtering |
| `/api/v1/sessions/active` | GET | Active sessions |
| `/api/v1/servers` | GET | List servers |
| `/api/v1/environments` | GET | List environments |

### Alert Settings

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/settings` | GET/POST | Global alert settings |
| `/api/v1/environments/<id>` | PUT | Update environment settings |
| `/api/v1/test-webhook` | POST | Test Slack webhook |

### Agent Endpoints (require API key)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/event` | POST | Receive session events |
| `/api/v1/heartbeat` | POST | Agent heartbeat |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Central Server                              │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐    │
│  │ Dashboard │  │ Sessions  │  │  Servers  │  │  Alerts   │    │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘    │
│                         │                                        │
│                    PostgreSQL                                    │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ HTTPS + API Key
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   [Production]          [Staging]              [Dev]
    Agents                Agents                Agents
```

## License

MIT
