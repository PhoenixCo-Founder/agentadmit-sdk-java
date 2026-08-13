# AgentAdmit SDK for Java (Spring Boot)

User-mediated AI agent authorization. Plug-and-play for any Spring Boot app.

> **Get started:** Sign up at [agentadmit.com](https://agentadmit.com) → Get your test keys → Install the SDK → Build.
> Test keys are available immediately after signup. Live keys become available when you subscribe an app.

## Quick Start

Add the dependency to your `pom.xml` or `build.gradle`. The SDK ships a Spring Boot auto-configuration (`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`), so no `@ComponentScan` or manual bean registration is needed -- the filter and scope-enforcement aspect activate automatically when the jar is on the classpath.

Configure via `application.yml`:

```yaml
# application.yml
agentadmit:
  app-id: ${AGENTADMIT_APP_ID}
  api-key: ${AGENTADMIT_API_KEY}
  verify-url: https://api.agentadmit.com/api/v1/verify
```

Both `verify-url` and `api-url` must be HTTPS. Plain HTTP is only permitted on loopback addresses (`localhost`, `127.0.0.1`, `[::1]`) for local development -- any other non-HTTPS URL causes a configuration exception at startup.

On startup you will see one INFO log line confirming enforcement is active:

```
AgentAdmit scope enforcement is active (filter + aspect registered).
```

Add scope enforcement to any endpoint:

```java
@GetMapping("/api/orders")
@RequireScope("read:orders")
public List<Order> getOrders(@AuthenticationPrincipal UserDetails user) {
    // Your existing logic -- unchanged
    return orderService.getOrdersForUser(user.getId());
}
```

Your app now supports AI agent connections with:
- Scoped access control (you define the scopes)
- User-controlled connection duration
- Token generation and exchange
- Mandatory introspection (every agent request validated through AgentAdmit)
- Revocation

## How It Works

1. User clicks "AgentAdmit" in your app
2. Selects scopes and connection duration
3. Gets a token to give to their AI agent
4. Agent exchanges the token for scoped API access
5. User revokes anytime

The token goes to the human, not the agent. No automated delivery = no prompt injection surface.

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**Admin revocation.** As the app operator, you can revoke any user's agent connection via `TokensClient#revoke(connectionId, reason)`, which calls the AgentAdmit hosted service. Use this from your own admin controllers.

**Embeddable admin panel.** Drop the `<AgentAdmitAdminPanel>` React component into your admin section to view all agent connections, usage metrics, billing status, and revoke any connection without leaving your app. See the React SDK for details.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

## Consent Ledger (Caller-Identity Consent)

AgentAdmit can host per-user consent switches for three independent caller classes: `human_session`, `in_app_ai`, and `external_agent`. No class's setting implies another's.

**External agents:** the verify result already carries the verdict:

```java
IntrospectionClient.IntrospectionResult result = introspectionClient.verify(token);
if (!result.consentGranted()) {
    // the data owner has switched external agents off: return your own 403
}
```

`consentGranted()` fails closed: an absent or malformed verdict is never a grant. The hosted service deliberately omits the consent block when its consent-store read fails (degraded mode), so when `result.consent()` is null, resolve the verdict through `ConsentClient.checkConsent(owner, ConsentClient.CALLER_CLASS_EXTERNAL_AGENT, scopeGroup)` before serving the request — `CallerConsentFilter` does this automatically.

**Human sessions and in-app AI** never hold AgentAdmit tokens, so ask directly:

```java
ConsentClient consent = new ConsentClient(config);
Map<String, Object> verdict = consent.checkConsent("user_8842", ConsentClient.CALLER_CLASS_IN_APP_AI, null);
if (Boolean.FALSE.equals(verdict.get("granted"))) {
    // do not run AI over this user's data
}
```

Consent is orthogonal to revocation: a denied verdict means your app returns its own 403; the connection and token stay valid so the user can flip consent back on without re-connecting. Write switches through `PUT /api/v1/consent/settings` from your backend; export the audit trail with `GET /api/v1/consent/export` (every plan).

**One-filter drop-in.** Instead of wiring the three paths by hand, `CallerConsentFilter` classifies the caller from the credential and evaluates the right independent path:

```java
CallerConsentFilter filter = new CallerConsentFilter(
    config, introspectionClient, consentClient,
    new CallerConsentFilter.Options(
        req -> req.getParameter("ownerId"),                       // resolveDataOwnerId
        req -> INTERNAL_SECRET.equals(req.getHeader("x-internal-ai"))
            ? "in_app_ai" : "human_session",                      // classifyNonAgent (credential structure, never caller input)
        "read:records",                                           // requiredScope (external agents)
        null,                                                     // scopeGroup
        false));                                                  // gateHuman
// Register after your own authentication filter. Downstream handlers read
// request attributes: agentadmit.callerClass, agentadmit.consent, and the
// standard agent attributes on the external-agent path.
```

External agents are checked via hosted introspection — the consent verdict is evaluated BEFORE the scope check, so a denied class never learns scope state, and an absent or malformed verdict is resolved through the Consent Ledger (fail closed; absence is never a grant); in-app AI via the Consent Ledger (fail closed); the human path defers to your own permission model unless `gateHuman` is true. It is a consent gate, not an authenticator, so register it after your own authentication.

## Presence Verification (WebAuthn Step-Up)

The verify result can carry a `presence` block stating whether the human who authorized the connection completed a WebAuthn presence ceremony on the consent page. Older servers omit it, and connections minted without a ceremony arrive with `verified: false`. Check it on the introspection result:

```java
IntrospectionClient.IntrospectionResult result = introspectionClient.verify(token);
if (!result.isPresenceVerified()) {
    // the connection was not authorized with a completed presence ceremony
}
```

`isPresenceVerified()` is strict and fails closed: it returns `true` only when the block is present and `verified` is a real boolean `true`. Absent, unverified, or malformed presence data all read as not verified, so responses from servers that predate the feature never pass.

For sensitive endpoints, enforce it declaratively the same way you enforce scopes:

```java
@PostMapping("/api/payments")
@RequirePresence
public Receipt createPayment(...) { ... }
```

Requests without an agent token get a 401 (matching `@RequireScope`); agent requests whose connection lacks a completed ceremony get a 403 `presence_required`. The raw `Presence` record (`verified`, `method`, `uv`, `verifiedAt`) is also available via `result.presence()` and the `agentadmit.presence` request attribute.

## Declared Purpose

Declared purpose: the user-facing reason recorded on the grant at the consent moment. It is a review-time record only, never an enforcement input — authorization decisions ride scopes, connection status, and consent.

Attach it when issuing a connection token (at most 300 characters):

```java
Map<String, Object> issued = tokensClient
    .issueToken("user_8842", List.of("read:orders"))
    .purpose("Reconcile Q3 invoices")
    .send();
```

When set, the SDK includes `purpose` in the token request body; when unset or null it is omitted. A purpose longer than 300 characters throws `IllegalArgumentException` before any request is sent.

The verify result carries it back for display:

```java
IntrospectionClient.IntrospectionResult result = introspectionClient.verify(token);
String purpose = result.purpose(); // null when the grant carries no declared purpose
```

`result.purpose()` is `null` when the grant has no declared purpose or the server predates the feature. Surface it in audit views, admin panels, and connection-review UIs — do not branch authorization on it.

## User-Declared Intent

User-declared intent: the user's own words, typed at the consent moment. Where `purpose` is the app's words for why the connection exists, `user_intent` is what the user themselves said they wanted. It is a review-time record only, never an enforcement input — authorization decisions ride scopes, connection status, and consent.

Attach it when issuing a connection token (at most 300 characters):

```java
Map<String, Object> issued = tokensClient
    .issueToken("user_8842", List.of("read:orders"))
    .purpose("Reconcile Q3 invoices")
    .userIntent("Match my September invoices against the bank statement")
    .send();
```

When set, the SDK includes `user_intent` in the token request body; when unset or null it is omitted. An intent longer than 300 characters throws `IllegalArgumentException` before any request is sent.

It flows identically to purpose — recorded on the grant, carried on verify, stamped onto audit rows and ledger events. When the hosted presence ceremony runs, the user-declared intent is included in the verifiable-consent-evidence commitment.

The verify result carries it back for display:

```java
IntrospectionClient.IntrospectionResult result = introspectionClient.verify(token);
String userIntent = result.userIntent(); // null when the grant carries no user-declared intent
```

`result.userIntent()` is `null` when the grant has no user-declared intent or the server predates the feature. Surface it in audit views, admin panels, and connection-review UIs — do not branch authorization on it.

## App-Attested Presence

If your app gates token minting behind its own embedded passkey/WebAuthn ceremony, AgentAdmit never witnesses that ceremony (it is origin-bound), so by default the hosted service reports `presence.verified: false` for those connections. Attest the ceremony fact at issuance to close that gap — AFTER verifying and consuming your own fresh, purpose-bound attestation:

```java
import java.time.Instant;

Map<String, Object> issued = tokensClient
    .issueToken("user_42", List.of("read:orders"))
    .presence(AppAttestedPresence.of("my_webauthn", attestation.createdAt()))
    .send();
```

The SDK sends it as `presence: {verified: true, uv: true, method, verified_at}` — `verified`/`uv` are literal true by construction and cannot represent anything else. The hosted service validates freshness (10-minute window, 60 s future clock-skew slack) and stores the method provenance-marked `app:<method>` so app-attested facts stay distinct from ceremonies AgentAdmit witnessed itself. Introspection, the grant-event ledger, and the evidence API then carry `presence.verified: true` for the connection.

Honesty ceiling: this is your app's attestation, recorded and provenance-marked. It is not witnessed by AgentAdmit and not independently verifiable. Only attest a ceremony that verified the user with UV (biometric or PIN user verification); a ceremony without UV carries no presence fact, so do not set one. An out-of-contract method (`^[a-z0-9_]+$`, 1-60) or a missing timestamp throws `IllegalArgumentException` at construction, before any request; `verified_at` serializes RFC 3339 with an explicit offset (the hosted contract).

## Rate Limiting

The AgentAdmit introspection endpoint enforces rate limits. The Java SDK handles HTTP 429 responses **automatically** with exponential backoff and jitter  --  no changes needed in your filter or aspect code.

### Retry behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1 second | First retry wait |
| Backoff multiplier | 2× | Doubles each retry |
| Cap | 30 seconds | Maximum wait per retry |
| Jitter | 0–500 ms | Random addition to each delay |
| Max retries | **3** | Configurable |

The SDK also respects the `Retry-After` response header  --  if present, it overrides the computed backoff delay.

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
- `getRetryAfter()`  --  seconds from `Retry-After` header (-1 if absent)
- `getLimit()`  --  `X-RateLimit-Limit` header value (-1 if absent)
- `getRemaining()`  --  `X-RateLimit-Remaining` header value (-1 if absent)
- `getReset()`  --  `X-RateLimit-Reset` Unix timestamp (-1 if absent)

## Documentation

Full integration guide: https://agentadmit.com/docs/app-owner-guide


## Data Collection & Privacy

The AgentAdmit Java SDK runs server-side and does not interact with app stores or end-user devices directly.

### What the SDK does
- Validates AgentAdmit tokens by calling AgentAdmit's hosted introspection endpoint (`https://api.agentadmit.com/api/v1/verify`) on every agent request  --  this is mandatory introspection; there is no local or offline validation mode
- Enforces scope-based access control on your API routes
- Manages connection lifecycle (create, revoke) via the AgentAdmit hosted service

### What the SDK does NOT do
- Does not transmit raw end-user PII (such as name, email, or device identifiers)  --  each introspection request sends the opaque access token and your API key
- Does not perform passive background telemetry or analytics  --  network calls occur only during active token validation
- Does not maintain its own persistent storage -- connection state and audit log are managed by the AgentAdmit hosted service

### What the AgentAdmit hosted service records
On every token validation, AgentAdmit's `/api/v1/verify` endpoint receives the access token and API key, resolves the token to its `user_id`, `connection_id`, granted `scopes`, and `agent_label`, and records per-call metadata (including the endpoint and timestamp) for billing, audit logging, the security alerts engine, and usage metering. This is integral to how AgentAdmit works and applies to both test and live keys. See the "Mandatory introspection" notes above and the [compliance guide](https://agentadmit.com/docs/compliance) for the full data-handling description.

### Privacy impact
Since this SDK runs on your server, it has no direct App Store or Play Store compliance surface. Your client-side integration (e.g., the AgentAdmit React SDK) handles privacy manifest and data safety requirements.

For complete compliance guidance, see our [compliance guide](https://agentadmit.com/docs/compliance).

## License

All rights reserved. Patent pending.

## Security Alerts

Inject `AlertsClient` into your Spring service and monitor suspicious agent activity.

```java
@Autowired
private AlertsClient alertsClient;
```

Six alert type constants: `ALERT_TYPE_VOLUME_SPIKE`, `ALERT_TYPE_FAILED_SCOPE_ATTEMPTS`, `ALERT_TYPE_BURST_PATTERN`, `ALERT_TYPE_STALE_REACTIVATION`, `ALERT_TYPE_NEW_SCOPE_USAGE`, `ALERT_TYPE_REVOKED_CONNECTION_ATTEMPT`.

### Configure Alert Thresholds

```java
Map<String, Object> result = alertsClient.configureAlerts(
    AlertsClient.ConfigureAlertsRequest.builder()
        .appId("app_abc123")
        .alertType(AlertsClient.ALERT_TYPE_VOLUME_SPIKE)
        .enabled(true)
        .thresholdValue(100.0)
        .thresholdWindowMinutes(5)
        .killSwitchEnabled(true)
        .build()
);
```

### List Alert Events

```java
Map<String, Object> events = alertsClient.listAlerts("app_abc123", null, AlertsClient.ALERT_TYPE_VOLUME_SPIKE);
```

### Get Current Config

```java
Map<String, Object> config = alertsClient.getAlertConfig("app_abc123");
```


### Notifying Your Users

AgentAdmit detects anomalies, fires alerts, and (with kill switch) auto-revokes connections. **How you notify your own users is up to you.** AgentAdmit provides the data  --  you deliver it through your own system (in-app notifications, email, push, etc.).

- **Poll alerts**  --  Use the SDK methods above from your backend to check for new events, then notify users through your existing system.
- **Webhook delivery**  --  Configure a webhook URL in your AgentAdmit dashboard. When an alert fires, AgentAdmit POSTs the payload to your server, signed with your `whsec_…` secret. The payload carries `alert_id`, `alert_type`, `severity`, the connection's `agent_label`, and the grant's declared `purpose`; the full shape is documented in the Webhook Delivery section of the MCP guide at https://agentadmit.com/docs/mcp-guide. Always verify the signature against the raw request body before trusting the payload:

  ```java
  @PostMapping("/agentadmit/alerts")
  public ResponseEntity<Void> alerts(@RequestBody byte[] payload,
                                     @RequestHeader("X-AgentAdmit-Signature") String signature) {
      try {
          Webhooks.verifySignature(payload, signature, webhookSecret); // whsec_…
      } catch (AgentAdmitException e) {
          return ResponseEntity.badRequest().build();
      }
      // payload is authentic  --  parse and handle the alert
      return ResponseEntity.ok().build();
  }
  ```

  The header format is `t=<unix_ts>,v1=<hex>`  --  an HMAC-SHA256 of `{t}.{rawBody}` keyed with your signing secret. Verification compares in constant time and rejects timestamps more than 5 minutes off (replay protection).
- **React SDK**  --  Embed the `<AlertsPanel>` component so users can view their own alert history and tighten thresholds.

### Issuing & Exchanging Tokens

```java
// duration is tri-state: omit both duration calls → AgentAdmit default (30 days);
// .durationUntilRevoked() → until the user revokes; .durationSeconds(n) → explicit.
Map<String, Object> issued = tokensClient
    .issueToken("user_42", List.of("read:orders"))
    .role("user")
    .durationUntilRevoked()
    .send();
String connectionToken = (String) issued.get("token"); // ag_ct_…

// Agent side  --  no API key needed; the connection token is the credential.
Map<String, Object> granted = tokensClient.exchange(connectionToken, "MyAssistant", null);

// Revoke when the user disconnects the agent.
tokensClient.revoke((String) granted.get("connection_id"), "user_requested");
```
