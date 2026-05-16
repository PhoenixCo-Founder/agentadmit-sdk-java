# AgentAdmit SDK for Java (Spring Boot)

User-mediated AI agent authorization. Plug-and-play for any Spring Boot app.

## Quick Start

Add the dependency to your `pom.xml` or `build.gradle`, then configure:

```yaml
# application.yml
agentadmit:
  app-id: ${AGENTADMIT_APP_ID}
  api-key: ${AGENTADMIT_API_KEY}
  verify-url: https://api.agentadmit.com/v1/verify
```

Add scope enforcement to any endpoint:

```java
@GetMapping("/api/orders")
@AgentAdmitScope("read:orders")
public List<Order> getOrders(@AuthenticationPrincipal UserDetails user) {
    // Your existing logic — unchanged
    return orderService.getOrdersForUser(user.getId());
}
```

Your app now supports AI agent connections with:
- Scoped access control (you define the scopes)
- User-controlled connection duration
- Token generation and exchange
- Mandatory introspection (every agent request validated through AgentAdmit)
- Revocation and audit logging
- Discovery endpoint at `/.well-known/agentadmit`

## How It Works

1. User clicks "AgentAdmit" in your app
2. Selects scopes and connection duration
3. Gets a token to give to their AI agent
4. Agent exchanges the token for scoped API access
5. User revokes anytime

The token goes to the human, not the agent. No automated delivery = no prompt injection surface.

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**Admin revocation.** As the app operator, you can revoke any user's agent connection via `DELETE /agentadmit/admin/connections/{connection_id}` (requires admin role or `manage:connections` scope).

**Embeddable admin panel.** Drop the `<AgentAdmitAdminPanel>` React component into your admin section to view all agent connections, usage metrics, billing status, and revoke any connection without leaving your app. See the React SDK for details.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

## Rate Limiting

The AgentAdmit introspection endpoint enforces rate limits. The Java SDK handles HTTP 429 responses **automatically** with exponential backoff and jitter — no changes needed in your filter or aspect code.

### Retry behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1 second | First retry wait |
| Backoff multiplier | 2× | Doubles each retry |
| Cap | 30 seconds | Maximum wait per retry |
| Jitter | 0–500 ms | Random addition to each delay |
| Max retries | **3** | Configurable |

The SDK also respects the `Retry-After` response header — if present, it overrides the computed backoff delay.

### Configuring max retries

In `application.yml`:

```yaml
agentadmit:
  max-retries: 5  # default: 3
```

### Handling exhausted retries

When all retries are exhausted, `IntrospectionClient.verify()` throws `AgentAdmitException.RateLimitError`:

```java
try {
    IntrospectionResult result = introspectionClient.verify(token);
} catch (AgentAdmitException.RateLimitError e) {
    response.setStatus(429);
    if (e.getRetryAfter() >= 0) {
        response.setHeader("Retry-After", String.valueOf((int) e.getRetryAfter()));
    }
    // e.getLimit(), e.getRemaining(), e.getReset()
}
```

`RateLimitError` methods:
- `getRetryAfter()` — seconds from `Retry-After` header (-1 if absent)
- `getLimit()` — `X-RateLimit-Limit` header value (-1 if absent)
- `getRemaining()` — `X-RateLimit-Remaining` header value (-1 if absent)
- `getReset()` — `X-RateLimit-Reset` Unix timestamp (-1 if absent)

## Documentation

Full integration guide: https://agentadmit.com/docs/app-owner-guide


## Data Collection & Privacy

The AgentAdmit Java SDK runs server-side and does not interact with app stores or end-user devices directly.

### What the SDK does
- Validates AgentAdmit tokens presented by AI agents
- Enforces scope-based access control on your API routes
- Manages connection lifecycle (create, revoke, audit)

### What the SDK does NOT do
- Does not collect end-user data
- Does not send telemetry or analytics
- Does not phone home to AgentAdmit servers (all operations use your configured keys and storage)
- Does not track users or devices

### Privacy impact
Since this SDK runs on your server, it has no direct App Store or Play Store compliance surface. Your client-side integration (e.g., the AgentAdmit React SDK) handles privacy manifest and data safety requirements.

For complete compliance guidance, see our [compliance guide](https://agentadmit.com/docs/compliance).

## License

All rights reserved. Patent pending.
