# Keycloak AAuth Protocol Extension

This extension provides the AAuth (Autonomous Authorization) protocol implementation for Keycloak, enabling machine-to-machine authentication and authorization flows as specified in the AAuth specification.

## Features

- **HTTP Message Signature Verification** (RFC 9421) for request authentication
- **AAuth Token Issuance** with agent identity binding
- **Multiple Grant Types**:
  - `auth` - Direct grant flow for machine-to-machine scenarios
  - `code` - Authorization code flow with user consent
  - `refresh` - Token refresh flow
  - `exchange` - Token exchange flow for delegation chains
- **Well-Known Endpoint** - `/.well-known/aauth-issuer` for issuer metadata
- **Policy Evaluation** - Configurable agent and scope policies
- **Federation Support** - Trust management for external auth servers

## Requirements

- Keycloak 26.2.5 or later
- Java 17 or later

## Installation

1. **Build the extension:**
   ```bash
   cd keycloak-aauth-extension
   mvn clean package
   ```

2. **Copy the JAR to Keycloak:**
   ```bash
   cp target/keycloak-aauth-extension-1.0.0.jar $KEYCLOAK_HOME/providers/
   ```

3. **Rebuild Keycloak:**
   ```bash
   cd $KEYCLOAK_HOME
   ./kc.sh build
   ```
   
   Or start Keycloak with optimization disabled:
   ```bash
   ./kc.sh start-dev
   ./kc.sh start-dev --log-level=org.keycloak.protocol.aauth:DEBUG
   ```

4. **Verify installation:**
   Check the Keycloak logs for:
   - `AAuthLoginProtocolFactory` registration
   - `AAuthSignatureFilter` registration
   - AAuth grant type factories registration

## Configuration

### Enable AAuth Protocol

AAuth protocol is enabled per realm. Configuration can be done via:

1. **Admin API:**
   ```bash
   curl -X PUT "http://localhost:8080/admin/realms/{realm}" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "attributes": {
         "aauth.enabled": "true"
       }
     }'
   ```

2. **Realm Attributes:**
   - `aauth.enabled` - Enable/disable AAuth protocol (default: false)
   - `aauth.allowed.agents` - Comma-separated list of allowed agent IDs
   - `aauth.allowed.scopes` - Comma-separated list of allowed scopes

### AAuth Scopes That Trigger User Consent

When an agent requests an auth token, the auth server evaluates the requested scopes to decide whether to return a `request_token` (requiring user consent) or an `auth_token` (direct grant). You can configure which scopes trigger the user consent flow via realm attributes.

**Realm attributes:**

| Attribute | Description |
|-----------|-------------|
| `aauth.consent.required.scopes` | JSON array of scope names that require user consent. Any requested scope that exactly matches an entry triggers the consent flow. |
| `aauth.consent.required.scope.prefixes` | JSON array of scope name prefixes. Any requested scope whose name starts with one of these prefixes triggers the consent flow. |

**Default behavior:** When both attributes are **not set** (missing or empty), the system uses defaults:
- **Exact matches:** `openid`, `profile`, `email`
- **Prefixes:** `user.`, `profile.`, `email.`

**Important:** Once you set either attribute (even to `[]`), the system uses **only** your configured lists and does not apply defaults. To restore defaults, remove the attributes entirely.

**Quick setup via script:**
```bash
./scripts/set_aauth_consent_attributes.sh [BASE_URL] [REALM_NAME] [ADMIN_USER] [ADMIN_PASSWORD]
```

**Example:**
```bash
./scripts/set_aauth_consent_attributes.sh http://localhost:8080 aauth-test admin admin
```

**Customize via environment variables:**
```bash
export AAUTH_CONSENT_SCOPES='["openid","profile","email","calendar.read"]'
export AAUTH_CONSENT_PREFIXES='["user.","profile.","email."]'
./scripts/set_aauth_consent_attributes.sh http://localhost:8080 aauth-test admin admin
```

**Manual configuration via Admin API:** Add the attributes to your realm JSON when updating the realm:
```json
{
  "attributes": {
    "aauth.consent.required.scopes": "[\"openid\",\"profile\",\"email\",\"calendar.read\"]",
    "aauth.consent.required.scope.prefixes": "[\"user.\",\"profile.\",\"email.\"]"
  }
}
```

**Examples:**
- `scope=openid` → `request_token` (exact match)
- `scope=user.preferences` → `request_token` (prefix match)
- `scope=data.read` → `auth_token` (no match, direct grant)

For detailed configuration, examples, and troubleshooting, see [docs/AAUTH_CONSENT_CONFIG.md](../docs/AAUTH_CONSENT_CONFIG.md).

### Agent Policies

Configure which agents are allowed to request tokens:

- **Allowed Agents:** List of agent HTTPS URLs or patterns
- **Allowed Scopes:** List of scopes that can be requested
- **Policy Evaluator:** Custom policy evaluation logic (via SPI)

## Usage

### Well-Known Endpoint

Get issuer metadata:
```bash
curl https://keycloak.example.com/realms/{realm}/.well-known/aauth-issuer
```

### Request Auth Token

**Direct Grant (no user consent):**
```bash
curl -X POST "https://keycloak.example.com/realms/{realm}/protocol/aauth/agent/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Signature-Key: keyid=\"...\", scheme=\"jwt\", ..." \
  -H "Signature-Input: sig1=..." \
  -H "Signature: sig1=:..." \
  -d "grant_type=auth&scope=read write&resource_id=https://resource.example.com"
```

**Authorization Code Flow (with user consent):**
```bash
# Step 1: Request authorization
curl "https://keycloak.example.com/realms/{realm}/protocol/aauth/agent/auth?request_token=..."

# Step 2: Exchange code for token
curl -X POST "https://keycloak.example.com/realms/{realm}/protocol/aauth/agent/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Signature-Key: ..." \
  -H "Signature-Input: ..." \
  -H "Signature: ..." \
  -d "grant_type=code&code=..."
```

## Architecture

### Components

- **Protocol Factory:** `AAuthLoginProtocolFactory` - Registers the AAuth protocol
- **Grant Types:** Four OAuth2 grant type implementations
- **HTTP Signature Filter:** `AAuthSignatureFilter` - Verifies HTTP Message Signatures
- **Token Manager:** `AAuthTokenManager` - Creates and validates AAuth tokens
- **Well-Known Provider:** `AAuthIssuerWellKnownProvider` - Serves issuer metadata
- **Policy Evaluator:** `AAuthPolicyEvaluator` - Evaluates authorization policies

### SPI Integration

The extension integrates with Keycloak via:

- `LoginProtocolFactory` SPI - Protocol registration
- `OAuth2GrantTypeFactory` SPI - Grant type registration
- `WellKnownProviderFactory` SPI - Well-known endpoint registration
- JAX-RS `@Provider` - Filter registration

## Limitations

- **Admin UI:** Admin UI components are not included in this extension. Configuration must be done via Admin API or realm attributes.
- **Internal APIs:** This extension uses some internal Keycloak APIs (from `server-spi-private` and `services` modules). These APIs may change in future Keycloak versions.
- **Version Compatibility:** Tested with Keycloak 26.2.5. Compatibility with other versions is not guaranteed.

## Development

### Building from Source

```bash
mvn clean install
```

### Project Structure

```
keycloak-aauth-extension/
├── pom.xml
├── README.md
└── src/
    └── main/
        ├── java/
        │   └── org/keycloak/protocol/aauth/
        │       ├── [Protocol implementation]
        │       ├── representations/  # Token representations
        │       └── util/             # Utility classes
        └── resources/
            └── META-INF/
                ├── beans.xml         # JAX-RS configuration
                └── services/         # SPI registrations
```

## Troubleshooting

### Filter Not Working

If HTTP signature verification is not working:

1. Check logs for filter registration messages
2. Verify `beans.xml` is present in the JAR
3. Ensure `@Provider` annotation is on `AAuthSignatureFilter`
4. Check that the filter is being called (enable debug logging)

### SPI Not Registered

If the protocol is not available:

1. Verify JAR is in `providers/` directory
2. Rebuild Keycloak: `./kc.sh build`
3. Check logs for SPI registration errors
4. Verify `META-INF/services/` files are correct

### Import Errors

If you see import errors:

1. Ensure all representation classes are in `org.keycloak.protocol.aauth.representations` package
2. Verify `AAuthJWKSUtils` is used instead of `JWKSUtils`
3. Check that all imports use the correct package paths

## License

Licensed under the Apache License, Version 2.0.

## Support

For issues and questions, please refer to the AAuth specification documentation or contact the maintainers.
