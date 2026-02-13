# salesrender/plugin-component-access

Security component for the SalesRender plugin ecosystem. Provides JWT-based authentication, RSA public key management, plugin registration (HPT token storage), and token handling for both incoming and outgoing requests between plugins and the SalesRender backend.

## Installation

```bash
composer require salesrender/plugin-component-access
```

## Requirements

- **PHP** >= 7.4.0
- **Extensions:** `ext-json`
- **Dependencies:**

| Package | Version | Purpose |
|---|---|---|
| `lcobucci/jwt` | 3.3.3 | JWT token parsing, creation, and verification |
| `league/uri` | 6.7.2 | URI parsing for issuer validation |
| `salesrender/plugin-component-db` | ^0.3.5 | Database model layer (Model, SinglePluginModelInterface) |
| `salesrender/plugin-component-guzzle` | ^0.3 | HTTP client for public key fetching and special requests |
| `salesrender/plugin-component-info` | ^0.1.2 | Plugin type information for output tokens |

## Architecture Overview

This component handles three core security concerns:

1. **Registration** -- storing the HandshakePluginToken (HPT) received during plugin registration
2. **PublicKey** -- fetching and caching the backend RSA public key for JWT verification
3. **Token** -- verifying incoming JWTs (RS512) and creating outgoing JWTs (HS512)

### Authentication Flow

```
SR Backend                              Plugin
    |                                     |
    |-- JWT (RS512, contains HPT) ------->|
    |                                     |-- Verify JWT with PublicKey
    |                                     |-- Extract HPT from JWT
    |                                     |-- Store HPT in Registration model
    |                                     |
    |<-- JWT (HS512, signed with HPT) ----|
    |                                     |
    |-- JWT (RS512, GraphQL request) ---->|
    |                                     |-- Verify with PublicKey::verify()
    |                                     |-- Create GraphqlInputToken
    |                                     |-- Process request
    |                                     |-- Create output JWT (HS512 with HPT)
    |<-- Response with output token ------|
```

- **Incoming tokens** from the backend are signed with RS512 (RSA private key). The plugin verifies them using the public key downloaded from the backend.
- **Outgoing tokens** created by the plugin are signed with HS512 (HMAC), using the stored HPT as the secret.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `LV_PLUGIN_SELF_URI` | Yes | The plugin's own URI. Used as the `aud` (audience) claim check during token verification |
| `LV_PLUGIN_COMPONENT_REGISTRATION_SCHEME` | No | URI scheme for issuer validation. Default: `https` |
| `LV_PLUGIN_COMPONENT_REGISTRATION_HOSTNAME` | No | Comma-separated list of allowed hostnames for the issuer. Default: `backend.leadvertex.com,backend.salesrender.com` |

## API Reference

### Registration

**Namespace:** `SalesRender\Plugin\Components\Access\Registration\Registration`

Extends `Model`, implements `SinglePluginModelInterface`. Stores the HPT (HandshakePluginToken) received during the plugin registration handshake with the SR backend.

#### Methods

| Method | Returns | Description |
|---|---|---|
| `__construct(Token $token)` | | Verifies the JWT via `PublicKey::verify()`, extracts HPT, cluster URI, country, and currency from claims |
| `static find()` | `?Model` | Finds the Registration record for the current plugin reference (inherited from SinglePluginModelInterface) |
| `getRegisteredAt()` | `int` | Unix timestamp of when the plugin was registered |
| `getHPT()` | `string` | The HandshakePluginToken -- the shared secret used for HS512 signing |
| `getCountry()` | `string` | 2-character country code from the registration token |
| `getCurrency()` | `string` | 3-character currency code from the registration token |
| `getClusterUri()` | `string` | The backend cluster URI (issuer) for building API endpoint URLs |
| `getSpecialRequestToken(array $body, int $ttl)` | `Token` | Creates an HS512-signed JWT with body payload and TTL for server-to-server communication |
| `makeSpecialRequest(string $method, string $uri, array $body, int $ttl)` | `ResponseInterface` | Creates a signed JWT and sends an HTTP request to the given URI |
| `static schema()` | `array` | Database schema definition |

#### Database Schema

| Column | Type | Constraint |
|---|---|---|
| `registeredAt` | INT | NOT NULL |
| `HPT` | VARCHAR(512) | NOT NULL |
| `country` | CHAR(2) | NOT NULL |
| `currency` | CHAR(3) | NOT NULL |
| `clusterUri` | VARCHAR(512) | NOT NULL |

---

### PublicKey

**Namespace:** `SalesRender\Plugin\Components\Access\PublicKey\PublicKey`

Extends `Model`. Manages RSA public keys used to verify JWT tokens from the SR backend. Keys are identified by their MD5 hash (the `pkey` header in JWT tokens) and cached in the database after the first download.

#### Methods

| Method | Returns | Description |
|---|---|---|
| `protected __construct(string $publicKey)` | | Sets `id` to `md5($publicKey)`, stores key content |
| `protected getPublicKey()` | `Key` | Returns the `Lcobucci\JWT\Signer\Key` instance |
| `static verify(Token $token)` | `bool` | Full token verification: audience, issuer scheme, issuer hostname, public key fetch/cache, RS512 signature |
| `static schema()` | `array` | Database schema definition |

#### Database Schema

| Column | Type | Constraint |
|---|---|---|
| `content` | TEXT | NOT NULL |

#### Verification Steps in `PublicKey::verify()`

1. **Audience check** -- the `aud` claim must match `$_ENV['LV_PLUGIN_SELF_URI']`
2. **Scheme check** -- the issuer (`iss`) URI scheme must match the configured scheme (default `https`)
3. **Hostname check** -- the issuer hostname must match one of the allowed hostnames (supports subdomain matching via regex)
4. **Key lookup** -- looks up a cached key by the `pkey` header hash; if not found, downloads from `{issuer_base}/pkey/{hash}`
5. **Signature verification** -- verifies the RS512 signature using the public key
6. **Key caching** -- saves the public key to the database if it was newly downloaded

---

### TokenVerificationException

**Namespace:** `SalesRender\Plugin\Components\Access\PublicKey\Exceptions\TokenVerificationException`

Extends `Exception`. Thrown by `PublicKey::verify()` with specific error codes:

| Code | Message | Meaning |
|---|---|---|
| 100 | Audience mismatched '{aud}' | Token's `aud` does not match `LV_PLUGIN_SELF_URI` |
| 200 | Issuer scheme is not '{scheme}' | Issuer URI uses the wrong scheme |
| 300 | Issuer hostname is not in '{hostnames}' | Issuer hostname not in the allowed list |
| 400 | Input token sign was not verified | RS512 signature verification failed |

---

### InputTokenInterface

**Namespace:** `SalesRender\Plugin\Components\Access\Token\InputTokenInterface`

Defines the contract for input token handlers.

| Method | Returns | Description |
|---|---|---|
| `__construct(string $token)` | | Parses and verifies the raw JWT string |
| `getId()` | `string` | JWT ID (`jti` claim) |
| `getCompanyId()` | `string` | Company ID (`cid` claim) |
| `getBackendUri()` | `string` | Backend URI (`iss` claim) |
| `getInputToken()` | `Token` | The parsed `Lcobucci\JWT\Token` instance |
| `getPluginReference()` | `PluginReference` | Plugin reference built from `cid` and `plugin` claims |
| `getOutputToken()` | `Token` | Creates an HS512-signed output JWT for backend communication |
| `static getInstance()` | `?InputTokenInterface` | Returns the singleton instance |
| `static setInstance(?InputTokenInterface $token)` | `void` | Sets the singleton instance |

---

### GraphqlInputToken

**Namespace:** `SalesRender\Plugin\Components\Access\Token\GraphqlInputToken`

Implements `InputTokenInterface`. Handles JWT tokens for GraphQL API requests. Uses the singleton pattern -- only one token can be active per request lifecycle.

| Method | Returns | Description |
|---|---|---|
| `__construct(string $token)` | | Parses JWT, verifies via `PublicKey::verify()`, throws `RuntimeException` if an instance already exists |
| `getInputToken()` | `Token` | Returns the parsed input JWT |
| `getPluginReference()` | `PluginReference` | Builds reference from `cid`, `plugin.alias`, `plugin.id` claims |
| `getId()` | `string` | Returns `jti` claim |
| `getCompanyId()` | `string` | Returns `cid` claim |
| `getBackendUri()` | `string` | Returns `iss` claim |
| `getOutputToken()` | `Token` | Creates an HS512-signed JWT containing the input JWT and plugin type, signed with HPT |
| `static getInstance()` | `?InputTokenInterface` | Returns the current singleton instance |
| `static setInstance(?InputTokenInterface $token)` | `void` | Sets or clears the singleton instance |

## Usage Examples

All examples below are taken from real plugins and plugin-core.

### 1. Plugin Registration (from [plugin-core](https://github.com/SalesRender/plugin-core) RegistrationAction)

The SR backend sends a JWT containing the HPT. The plugin parses the token, sets the plugin reference, and stores the Registration model:

```php
use Lcobucci\JWT\Parser;
use SalesRender\Plugin\Components\Access\Registration\Registration;
use SalesRender\Plugin\Components\Db\Components\Connector;
use SalesRender\Plugin\Components\Db\Components\PluginReference;

// Parse registration JWT from request body
$parser = new Parser();
$token = $parser->parse($request->getParsedBodyParam('registration'));

// Set the plugin reference from token claims
Connector::setReference(new PluginReference(
    $token->getClaim('cid'),
    $token->getClaim('plugin')->alias,
    $token->getClaim('plugin')->id
));

// Delete old registration if exists
if ($old = Registration::find()) {
    $old->delete();
}

// Create and save new registration (verifies JWT internally)
$registration = new Registration($token);
$registration->save();
```

### 2. Protected Middleware -- Verifying Incoming Requests (from [plugin-core](https://github.com/SalesRender/plugin-core) ProtectedMiddleware)

Every protected endpoint verifies the incoming JWT via the `X-PLUGIN-TOKEN` header:

```php
use SalesRender\Plugin\Components\Access\Registration\Registration;
use SalesRender\Plugin\Components\Access\Token\GraphqlInputToken;
use SalesRender\Plugin\Components\Db\Components\Connector;

// Extract JWT from header
$jwt = $request->getHeader('X-PLUGIN-TOKEN')[0] ?? '';

if (empty($jwt)) {
    throw new HttpException($request, 'X-PLUGIN-TOKEN not found', 401);
}

try {
    // Parse and verify the JWT (RS512 verification happens inside)
    $token = new GraphqlInputToken($jwt);
    GraphqlInputToken::setInstance($token);
} catch (Exception $exception) {
    throw new HttpException($request, $exception->getMessage(), 403);
}

// Set plugin reference for scoped database queries
Connector::setReference($token->getPluginReference());

// Ensure the plugin has been registered
if (Registration::find() === null) {
    throw new HttpException($request, 'Plugin was not registered', 403);
}
```

### 3. Using Output Token for API Requests (from [plugin-macros-example](https://github.com/SalesRender/plugin-macros-example))

After verification, the output token is used to authenticate requests back to the backend:

```php
use SalesRender\Plugin\Components\Access\Token\GraphqlInputToken;
use SalesRender\Plugin\Components\ApiClient\ApiClient;

$token = GraphqlInputToken::getInstance();
$client = new ApiClient(
    $token->getBackendUri() . 'companies/stark-industries/CRM',
    (string) $token->getOutputToken()
);
```

### 4. Making Special Requests to Backend (from [plugin-core-logistic](https://github.com/SalesRender/plugin-core-logistic) BatchShippingHandler)

The `makeSpecialRequest` method creates an HS512-signed JWT and sends it to the backend:

```php
use SalesRender\Plugin\Components\Access\Registration\Registration;

// Add orders to a shipping batch
Registration::find()->makeSpecialRequest(
    'PATCH',
    $uri,
    [
        'shippingId' => $shippingId,
        'orders' => $orders,
        'lockId' => $this->lockId,
    ],
    60 * 10 // TTL: 10 minutes
);
```

### 5. Creating Special Request Tokens Manually (from [plugin-core-pbx](https://github.com/SalesRender/plugin-core-pbx) CdrSender)

When you need to pass the token string to a deferred request dispatcher rather than sending immediately:

```php
use SalesRender\Plugin\Components\Access\Registration\Registration;
use SalesRender\Plugin\Components\Db\Components\Connector;
use XAKEPEHOK\Path\Path;

$registration = Registration::find();
$uri = (new Path($registration->getClusterUri()))
    ->down('companies')
    ->down(Connector::getReference()->getCompanyId())
    ->down('CRM/plugin/pbx/cdr');

$ttl = 60 * 60 * 24; // 24 hours
$jwt = $registration->getSpecialRequestToken($this->cdr, $ttl);

// Use the token string in a deferred request
$request = new SpecialRequest(
    'PATCH',
    (string) $uri,
    (string) $jwt,
    time() + $ttl,
    202
);
```

### 6. Integration Plugin -- Sending GraphQL Mutations (from plugin-integration-taplink)

Using `makeSpecialRequest` to execute GraphQL mutations on the backend:

```php
use SalesRender\Plugin\Components\Access\Registration\Registration;
use SalesRender\Plugin\Components\Db\Components\Connector;

$registration = Registration::find();
$reference = Connector::getReference();

$registration->makeSpecialRequest(
    'POST',
    "{$registration->getClusterUri()}/companies/{$reference->getCompanyId()}/CRM/plugin/integration",
    [
        'query' => 'mutation ($input: AddOrderInput!) { orderMutation { addOrder(input: $input) { id } } }',
        'variables' => ['input' => $variables],
    ],
    300 // TTL: 5 minutes
);
```

### 7. Verifying Special Requests (from [plugin-core](https://github.com/SalesRender/plugin-core) SpecialRequestAction)

Incoming special requests from the backend are verified using `PublicKey::verify()` directly:

```php
use Lcobucci\JWT\Parser;
use SalesRender\Plugin\Components\Access\PublicKey\PublicKey;
use SalesRender\Plugin\Components\Access\Registration\Registration;

$token = (new Parser())->parse($request->getParsedBodyParam('request'));
PublicKey::verify($token);
$claims = json_decode(json_encode($token->getClaims()), true);

// Verify registration exists
if (Registration::find() === null) {
    throw new HttpException($request, 'Plugin was not registered', 403);
}
```

### 8. Checking Settings Access (from [plugin-core](https://github.com/SalesRender/plugin-core) SettingsAccessMiddleware)

Reading claims from the verified token singleton to check permissions:

```php
use SalesRender\Plugin\Components\Access\Token\GraphqlInputToken;

$isSettingsAllowed = GraphqlInputToken::getInstance()
    ->getInputToken()
    ->getClaim('settings', false);

if (!$isSettingsAllowed) {
    throw new HttpException($request, 'Access to settings is not allowed', 403);
}
```

### 9. Reading Registration Metadata (from plugin-logistic-sphere)

Accessing the country and currency stored during registration:

```php
use SalesRender\Plugin\Components\Access\Registration\Registration;

$currency = Registration::find()->getCurrency(); // e.g., "USD"
```

### 10. Batch Operations -- Using GraphqlInputToken Singleton (from [plugin-core](https://github.com/SalesRender/plugin-core) BatchPrepareAction)

The token singleton is shared across the request lifecycle:

```php
use SalesRender\Plugin\Components\Access\Token\GraphqlInputToken;
use SalesRender\Plugin\Components\Batch\Batch;

$batch = new Batch(
    GraphqlInputToken::getInstance(),
    new ApiFilterSortPaginate($filters, $sort, 100),
    Translator::getLang(),
    $request->getParam('arguments', [])
);
$batch->save();
```

## JWT Claim Structure

### Incoming JWT from Backend (RS512)

| Claim/Header | Description |
|---|---|
| `pkey` (header) | MD5 hash of the public key used for signing |
| `iss` | Issuer -- backend cluster URI (e.g., `https://backend.salesrender.com`) |
| `aud` | Audience -- plugin's own URI (`LV_PLUGIN_SELF_URI`) |
| `cid` | Company ID |
| `plugin` | Object with `alias` and `id` fields |
| `jti` | JWT ID (unique identifier) |
| `HPT` | HandshakePluginToken (only present in registration tokens) |
| `country` | 2-character country code (only in registration tokens) |
| `currency` | 3-character currency code (only in registration tokens) |
| `settings` | Boolean flag indicating whether settings access is allowed (in GraphQL tokens) |

### Outgoing JWT from Plugin (HS512)

#### Output Token (GraphqlInputToken::getOutputToken)

| Claim | Description |
|---|---|
| `jwt` | The original input JWT string |
| `plugin` | Plugin type from `Info::getInstance()->getType()` |

#### Special Request Token (Registration::getSpecialRequestToken)

| Claim | Description |
|---|---|
| `iss` | Plugin's own URI (`LV_PLUGIN_SELF_URI`) |
| `aud` | Backend cluster URI |
| `cid` | Company ID |
| `plugin` | Object with `alias` and `id` |
| `body` | Request payload array |
| `exp` | Expiration time (`time() + $ttl`) |

## See Also

- [salesrender/plugin-component-db](https://github.com/SalesRender/plugin-component-db) -- Database model layer, `Model`, `SinglePluginModelInterface`
- [salesrender/plugin-component-guzzle](https://github.com/SalesRender/plugin-component-guzzle) -- HTTP client used for public key download and special requests
- [salesrender/plugin-component-info](https://github.com/SalesRender/plugin-component-info) -- Plugin info/type metadata
- [salesrender/plugin-core](https://github.com/SalesRender/plugin-core) -- Core plugin framework with `ProtectedMiddleware`, `RegistrationAction`, `SpecialRequestAction`
