# Security Guide

This document outlines the security features and considerations for the Cloudflare Workers S3 Proxy.

## URL Signature Validation

### Overview

The proxy supports URL signature validation for secure access control. When `URL_SIGNING_SECRET` is configured, all
requests must include valid signatures to access protected resources.

### AWS S3 Signature Version 4 Compliance

The signature validation implementation follows AWS S3 Signature Version 4 standards for maximum compatibility and
security:

#### Canonical Query String Construction

1. **RFC3986 Encoding**: Parameter names and values are encoded using RFC3986 standard where:
    - Spaces are encoded as `%20` (not `+`)
    - Special characters `!'()*` are percent-encoded
    - All other characters follow standard `encodeURIComponent()` rules

2. **Parameter Sorting**: Query parameters are sorted alphabetically by name (case-sensitive)

3. **Trailing `?` Handling**: The canonical request only includes `?` when query parameters exist:
    - With parameters: `pathname?param1=value1&param2=value2`
    - Without parameters: `pathname` (no trailing `?`)

#### Signature Generation Process

**Client-Side (using `src/generate_signed_url.js`):**

```javascript
// 1. Add expiration parameter
url.searchParams.set("exp", expirationTimestamp.toString());

// 2. Create canonical query string (excluding 'sig')
const canonicalQueryString = createCanonicalQueryString(url.searchParams, "sig");

// 3. Construct data to sign
const dataToSign = canonicalQueryString
    ? `${url.pathname}?${canonicalQueryString}`
    : url.pathname;

// 4. Generate HMAC-SHA256 signature
const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(dataToSign));
```

**Server-Side Verification:**

- Identical canonical query string construction
- Same RFC3986 encoding rules
- Exact match of `dataToSign` format

### Security Error Codes

The implementation returns appropriate HTTP status codes for different security scenarios:

- **403 Forbidden**: Invalid or missing signatures, expired URLs, malformed signature format
- **401 Unauthorized**: Reserved for other authentication methods (not signature validation)

This follows security best practices where signature validation failures are authorization issues (403), not
authentication issues (401).

### Cache Security

#### Signature Parameter Exclusion

**CRITICAL**: Signature parameters (`sig`, `exp`) are automatically excluded from cache keys to ensure:

1. **Separate Caching**: Signed and unsigned requests for the same content are cached together
2. **Cache Efficiency**: Different signatures for identical content don't create unnecessary cache misses
3. **Security**: Expired signatures cannot serve cached content inappropriately
4. **Attack Prevention**: Cache poisoning via signature manipulation is prevented

#### Cache Key Generation

```typescript
// Security-aware cache key generation
const signatureParams = ["sig", "exp"]; // Excluded from cache keys
const cacheBustingParams = ["_", "bust", "nocache", "v", "version"];
const paramsToExclude = [...signatureParams, ...cacheBustingParams];
```

## Environment Variable Security

### Required Security Variables

- `URL_SIGNING_SECRET`: Strong secret key for HMAC signature generation/verification
- `CACHE_PURGE_SECRET`: Authentication token for cache purging operations

### Optional Security Variables

- `CORS_ALLOW_ORIGINS`: Restrict cross-origin access to specific domains

## Implementation Security Features

### Input Validation

1. **Path Traversal Protection**: Comprehensive filename validation prevents directory traversal attacks
2. **Parameter Validation**: All environment variables are validated with appropriate constraints
3. **Signature Format Validation**: Hex signature format is strictly validated

### Error Handling

1. **Information Disclosure Prevention**: Error messages don't reveal internal system details
2. **Consistent Error Responses**: All errors return JSON format for consistent handling
3. **Rate Limiting Ready**: Metrics tracking supports future rate limiting implementation

### Cryptographic Security

1. **HMAC-SHA256**: Industry-standard algorithm for signature generation
2. **Timing Attack Resistance**: Uses `crypto.subtle.verify()` for constant-time comparison
3. **Key Management**: Secrets are only accessed from environment variables

## Best Practices

### URL Signing

1. **Short Expiration Times**: Use reasonable expiration windows (e.g., 1-24 hours)
2. **Secure Secret Management**: Store `URL_SIGNING_SECRET` securely in Cloudflare Workers secrets
3. **Client-Side Mirroring**: Ensure client-side generation exactly matches server validation

### Deployment Security

1. **Environment Isolation**: Use different secrets for development/staging/production
2. **Secret Rotation**: Regularly rotate `URL_SIGNING_SECRET` and update clients
3. **Monitoring**: Monitor signature validation failures for potential attacks

### Cache Security

1. **TTL Limits**: Configure appropriate `CACHE_MIN_TTL_SECONDS` and `CACHE_MAX_TTL_SECONDS`
2. **Purge Controls**: Restrict `CACHE_PURGE_SECRET` to authorized personnel only
3. **Debug Mode**: Only enable `CACHE_DEBUG` in development environments

## Testing Signature Validation

### Generate Test URLs

```bash
# Set your secret
export URL_SIGNING_SECRET="your-secret-key"

# Generate signed URL
node src/generate_signed_url.js
```

### Validate Implementation

1. **Positive Tests**: Valid signatures should return requested content
2. **Negative Tests**: Invalid/expired signatures should return 403 errors
3. **Edge Cases**: Test with various query parameters, special characters, and empty paths

### Security Verification

1. **Signature Tampering**: Modify signature - should return 403
2. **Expiration Testing**: Use expired timestamp - should return 403
3. **Parameter Injection**: Add extra parameters - signature should remain valid
4. **Cache Verification**: Same content with different signatures should cache together

## Monitoring and Alerting

### Key Metrics

- `worker_errors_total`: Monitor for unusual signature validation failures
- `worker_cache_hits_total` / `worker_cache_misses_total`: Verify cache efficiency
- `worker_not_modified_responses_total`: Track conditional request performance

### Security Events to Monitor

1. High rate of 403 errors (potential attack)
2. Unusual geographic distribution of signature failures
3. Cache purge requests from unauthorized sources
4. Environment validation failures at startup 