# Cloudflare Workers S3 Proxy

![Cloudflare Workers](https://img.shields.io/badge/cloudflare%20workers-F38020?style=for-the-badge&logo=cloudflare) ![Hono](https://img.shields.io/badge/hono-E36002?style=for-the-badge&logo=hono) ![MIT License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

A lightweight, cache‑friendly proxy that lets you serve objects from any S3‑compatible storage (Backblaze B2, MinIO,DigitalOcean Spaces, etc.) through the Cloudflare edge. Perfect for static asset hosting, private downloads, or as adrop‑in CDN for existing buckets.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Signed URLs](#signed-urls)
- [Cache Management](#cache-management)
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Edge‑level Authentication** – Optional signed URLs with expiration.
- **Range Requests & Partial Responses** – Stream video, large files, and resume interrupted downloads.
- **Advanced Cache Management** – Intelligent caching with TTL control, metrics, and purging.
- **Automatic Path Normalisation** – Protection against directory traversal.
- **Flexible CORS** – Fine‑grained per‑origin allow‑list via environment variable.
- **Health Check** endpoint.
- **Built with [Hono](https://honojs.dev) on Cloudflare Workers** for minimal cold starts.

## Quick Start

```bash
# Prerequisites: Node.js ≥ 18, Wrangler ≥ 3, a Cloudflare account

# 1. Install dependencies
npm install

# 2. Copy the sample env file and update values
cp .dev.vars.template .dev.vars

# 3. Start a local dev server
npm run dev
```

## Deployment

```bash
# Deploy to your Cloudflare account authenticated with `wrangler login`

npm run deploy
```

Ensure `wrangler.toml` contains the **\[vars]** block below.

## Configuration

| Variable                     | Description                             | Example                                       | Required |
| ---------------------------- | --------------------------------------- | --------------------------------------------- | -------- |
| `END_POINT`                  | S3 API endpoint                         | `https://s3.us-west-1.amazonaws.com`          | Yes      |
| `ACCESS_KEY`                 | S3 access key ID                        | `AKIAEXAMPLE`                                 | Yes      |
| `SECRET_KEY`                 | S3 secret access key                    | `wJalrX...`                                   | Yes      |
| `BUCKET_NAME`                | S3 bucket to proxy                      | `my-assets`                                   | Yes      |
| `S3_REGION`                  | AWS region for S3 operations            | `us-west-1`                                   | Yes      |
| `RANGE_RETRY_ATTEMPTS`       | Max retries for range requests          | `3`                                           | Yes      |
| `URL_SIGNING_SECRET`         | HMAC secret for signed URLs             | `super-secret-32-chars-minimum`               | No       |
| `CORS_ALLOW_ORIGINS`         | Comma-separated CORS origins            | `https://example.com,https://app.example.com` | No       |
| `VERSION`                    | Version identifier                      | `v1.0.0`                                      | No       |
| `CACHE_ENABLED`              | Enable caching system                   | `true`                                        | No       |
| `CACHE_TTL_SECONDS`          | Default cache TTL (1-604800)            | `3600`                                        | No       |
| `CACHE_DEBUG`                | Enable cache debug headers              | `false`                                       | No       |
| `CACHE_MIN_TTL_SECONDS`      | Minimum cache TTL (1-86400)             | `60`                                          | No       |
| `CACHE_MAX_TTL_SECONDS`      | Maximum cache TTL (60-604800)           | `86400`                                       | No       |
| `CACHE_OVERRIDE_S3_HEADERS`  | Override S3 cache headers               | `false`                                       | No       |
| `CACHE_PURGE_SECRET`         | Secret for cache purge operations       | `your-secure-secret`                          | No       |
| `ENFORCE_URL_SIGNING`        | Require URL signing for all requests    | `false`                                       | No       |
| `URL_SIGNING_REQUIRED_PATHS` | Comma-separated paths requiring signing | `/private,/secure`                            | No       |
| `ENABLE_LIST_ENDPOINT`       | Enable directory listing endpoint       | `true`                                        | No       |
| `ENABLE_UPLOAD_ENDPOINT`     | Enable file upload endpoints            | `true`                                        | No       |
| `ENABLE_DELETE_ENDPOINT`     | Enable file deletion endpoints          | `true`                                        | No       |
| `PREFIX_MAX_LENGTH`          | Maximum prefix length (1-1024)          | `256`                                         | No       |
| `PREFIX_MAX_DEPTH`           | Maximum prefix depth (1-50)             | `10`                                          | No       |

Example `wrangler.jsonc` snippet:

```jsonc
{
  "name": "my-s3-proxy",
  "main": "src/index.ts",
  "compatibility_date": "2025-01-01",
  "vars": {
    "END_POINT": "https://s3.us-west-1.amazonaws.com",
    "ACCESS_KEY": "AKIAEXAMPLE",
    "SECRET_KEY": "wJalrX...",
    "BUCKET_NAME": "my-assets",
    "S3_REGION": "us-west-1",
    "RANGE_RETRY_ATTEMPTS": 3,
    "CORS_ALLOW_ORIGINS": "https://example.com",
    "VERSION": "v1.0.0",
    "CACHE_ENABLED": true,
    "CACHE_TTL_SECONDS": 3600,
    "CACHE_DEBUG": false,
    "CACHE_MIN_TTL_SECONDS": 60,
    "CACHE_MAX_TTL_SECONDS": 86400,
    "CACHE_OVERRIDE_S3_HEADERS": false,
    "CACHE_PURGE_SECRET": "your-secure-secret",
    "ENABLE_LIST_ENDPOINT": true,
    "ENABLE_UPLOAD_ENDPOINT": true,
    "ENABLE_DELETE_ENDPOINT": true
  }
}
```

## API Reference

### `GET /list?prefix=<path/>`

Returns the object keys directly under the given prefix.

```json
{
  "keys": ["images/a.jpg", "images/b.png"]
}
```

### `GET /<key>[?download[=name]|inline]`

Fetches the object as‑is. Supports HTTP `Range` headers.

- `download` – forces `Content‑Disposition: attachment` (optionally override filename).
- `inline` – forces `Content‑Disposition: inline`.

Examples:

```
GET /images/a.jpg
GET /images/a.jpg?download
GET /images/a.jpg?download=foo.png
GET /images/a.jpg?inline
```

### `PUT /<filename>`

Uploads a file. The worker streams the request body directly to S3.Relevant headers like `Content-Type`, `Content-MD5`, `Content-Length`, `Content-Encoding`, `Cache-Control`,`x-amz-meta-*`, `x-amz-checksum-*`, and S3 server-side encryption headers are forwarded to S3.
If URL signing is enabled, PUT requests must be signed.

### `POST /presigned-upload`

Generates a presigned S3 URL for PUT uploads.
Request body:

```json
{
  "key": "path/to/your/object.txt",
  "expiresIn": 3600,
  // Optional: expiration in seconds (default 3600, max 7 days)
  "conditions": {
    // Optional: conditions for the upload
    "contentType": "text/plain",
    "contentLength": 1024,
    // in bytes
    "contentMd5": "base64-md5-hash",
    "metadata": {
      "custom-key": "custom-value"
    }
  }
}
```

Response:

```json
{
  "presignedUrl": "...",
  "key": "path/to/your/object.txt",
  "expiresIn": 3600,
  "expiresAt": "...",
  "method": "PUT",
  "requiredHeaders": {
    ...
  }
}
```

### Multipart Upload Endpoints

**Note**: Multipart upload functionality is currently being enhanced. Complete documentation will be available soon.

#### `POST /<filename>/uploads`

Initiates a multipart upload.

#### `PUT /<filename>?partNumber=X&uploadId=Y`

Uploads a part of a multipart upload.

#### `POST /<filename>?uploadId=Y`

Completes a multipart upload.

#### `DELETE /<filename>?uploadId=Y`

Aborts a multipart upload.

_Detailed documentation for multipart upload workflows, XML formats, and examples will be added in the next update._

### `DELETE /<filename>`

Deletes a file. An optional`versionId` query parameter can be included. Returns a 200 OK with a JSON body indicating success. If URL signing is enabled, DELETE requests must be signed.

### `POST /delete`

Batch deletes files.
Request body:

```json
{
  "keys": ["path/to/object1.txt", "path/to/object2.jpg"],
  "quiet": false
  // Optional: if true, S3 returns success even if some keys fail (default false)
}
```

A maximum of 1000 keys can be specified. The S3 XML response detailing the result for each key is returned (unless`quiet` is `true`). If URL signing is enabled, this endpoint can be protected.

### `GET /__health`

Returns build version and server time. Useful for liveness probes.

### `GET /__cache/stats`

Returns detailed cache statistics including hit rates, configuration, and performance metrics.

```json
{
  "config": {
    "enabled": true,
    "ttlSeconds": 3600,
    "overrideS3Headers": false
    // ... more config ...
  },
  "metrics": {
    "cacheHits": 1250,
    "cacheMisses": 180
    // ... more metrics ...
  },
  "performance": {
    // ... performance data ...
  }
}
```

### `GET /__cache/health`

Returns the health status of the cache system.

```json
{
  "status": "healthy",
  "message": "Cache is functioning normally"
  // ... more details ...
}
```

### `POST /__cache/purge`

Authenticated endpoint for cache invalidation. Requires `Authorization: Bearer <CACHE_PURGE_SECRET>` header.

Purge by specific keys:

```bash
curl -X POST /__cache/purge \
  -H "Authorization: Bearer your-secure-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "keys": ["/path/to/file1.jpg", "/path/to/file2.pdf"]
  }'
```

Purge by pattern (future support):

```bash
curl -X POST /__cache/purge \
  -H "Authorization: Bearer your-secure-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "pattern": "^/images/.*\.jpg$"
  }'
```

### `POST /__cache/warm`

Authenticated endpoint for proactive cache population. Requires `Authorization: Bearer <CACHE_PURGE_SECRET>` header.

```bash
curl -X POST /__cache/warm \
  -H "Authorization: Bearer your-secure-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://your-worker.example.com/popular-file1.jpg",
      "https://your-worker.example.com/popular-file2.pdf"
    ]
  }'
```

## Signed URLs

URL signing provides secure, time-limited access to files. Configure the `URL_SIGNING_SECRET` environment variable to enable this feature.

Signed URLs include:

- `exp`: Expiration timestamp
- `sig`: HMAC-SHA256 signature

Example signed URL format:

```
https://worker.example.com/private/report.pdf?exp=1710000000&sig=abcdef...
```

Refer to the documentation for URL signing implementation details and security best practices.

## Cache Management

This proxy includes a significantly enhanced cache management system that provides better performance, more control, and comprehensive cache operations. Key features include:

- **Hybrid Caching Strategy**: Combines Cloudflare's edge caching with the Cache API.
- **Enhanced Conditional Request Handling**: ETag and Last-Modified support.
- **Advanced Cache Invalidation & Management**: Selective and pattern-based purging, cache warming.
- **Advanced Analytics & Debugging**: Detailed metrics, debug headers, and real-time statistics.

### Cache Endpoints

- `GET /__cache/stats` – Detailed cache statistics and performance metrics.
- `GET /__cache/health` – Health status of the cache system.
- `POST /__cache/purge` – Authenticated cache invalidation endpoint.
- `POST /__cache/warm` – Authenticated endpoint for proactive cache population.

For complete documentation on configuration, best practices, and troubleshooting, see **[docs/cache-management.md](./docs/cache-management.md)**.

## Security Notes

This proxy implements comprehensive security features for production use, including:

- **Enhanced URL Signature Validation**
- **Path Traversal Protection**
- **Cache Security**
- **Constant-Time Verification**
- **Appropriate Error Codes**
- **CORS Protection**

For complete security documentation, implementation details, and best practices, see **[docs/security.md](./docs/security.md)**.

## Roadmap

- Object upload endpoint
- ETag‑aware caching
- Terraform module for one‑command deploy

## Contributing

Pull requests are welcome! Please open an issue first to discuss major changes.

## License

MIT © 2025 Shogo Ishigami

---

### Contact

Found a bug? Have a question? [Open an issue](https://github.com/nusu-github/cf-workers-s3-proxy/issues) and we'll take
a look.
