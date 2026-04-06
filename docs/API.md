# Admin API

## Overview

The WAF Admin API provides RESTful endpoints for managing rules, viewing statistics, and configuring the WAF.

Base URL: `http://localhost:8081/api`

## Authentication

API key authentication via `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8081/api/rules
```

## Endpoints

### Rules

#### List All Rules
```
GET /api/rules
```

Response:
```json
[
  {
    "id": "sqli-001",
    "name": "SQL Injection Detection",
    "severity": "critical",
    "enabled": true,
    "priority": 100,
    "conditions": [...],
    "action": {...}
  }
]
```

#### Get Single Rule
```
GET /api/rules/:id
```

#### Create Rule
```
POST /api/rules
Content-Type: application/json

{
  "id": "custom-001",
  "name": "Custom Rule",
  "severity": "high",
  "enabled": true,
  "conditions": [...],
  "action": {...}
}
```

#### Update Rule
```
PUT /api/rules/:id
Content-Type: application/json

{...}
```

#### Delete Rule
```
DELETE /api/rules/:id
```

### Statistics

#### Overall Statistics
```
GET /api/stats
```

Response:
```json
{
  "total_requests": 12345,
  "blocked_requests": 67,
  "allowed_requests": 12278,
  "block_rate": 0.0054
}
```

#### Attack Statistics
```
GET /api/stats/attacks
```

Response:
```json
{
  "sqli": 23,
  "xss": 15,
  "path_traversal": 8,
  "command_injection": 5
}
```

#### Traffic Statistics
```
GET /api/stats/traffic
```

Response:
```json
{
  "requests_per_minute": 100,
  "bytes_transferred": 1024000,
  "avg_latency_ms": 5.2
}
```

### Logs

#### Get Attack Logs
```
GET /api/logs?offset=0&limit=100
```

Response:
```json
[
  {
    "id": "log-123",
    "timestamp": "2024-01-15T10:30:00Z",
    "client_ip": "192.168.1.1",
    "attack_type": "sqli",
    "severity": "critical",
    "rule_id": "sqli-001",
    "uri": "/api/users",
    "matched_value": "UNION SELECT"
  }
]
```

### Configuration

#### Get Configuration
```
GET /api/config
```

#### Update Configuration
```
PUT /api/config
Content-Type: application/json

{...}
```

### Health

#### Health Check
```
GET /health
```

Response: `OK`

## Error Responses

| Status | Description |
|--------|-------------|
| 400 | Bad Request - Invalid input |
| 404 | Not Found - Resource doesn't exist |
| 500 | Internal Server Error |

Error format:
```json
{
  "error": "Invalid rule format",
  "details": "Missing required field: name"
}
```

## Rate Limits

API is rate-limited to 100 requests per minute per IP.

## WebSocket (Future)

Real-time updates via WebSocket at `/ws`:
```javascript
const ws = new WebSocket('ws://localhost:8081/ws');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('New attack:', data);
};
```