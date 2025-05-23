# Cloudflare Workers S3 Proxy

![Cloudflare Workers](https://img.shields.io/badge/cloudflare%20workers-F38020?style=for-the-badge\&logo=cloudflare) ![Hono](https://img.shields.io/badge/hono-E36002?style=for-the-badge\&logo=hono) ![MIT License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

A lightweight, cache‑friendly proxy that lets you serve objects from any S3‑compatible storage (Backblaze B2, MinIO,DigitalOcean Spaces, etc.) through the Cloudflare edge. Perfect for static asset hosting, private downloads, or as adrop‑in CDN for existing buckets.

## Table of Contents

* [Features](#features)
* [Quick Start](#quick-start)
* [Deployment](#deployment)
* [Configuration](#configuration)
* [API Reference](#api-reference)
* [Signed URLs](#signed-urls)
* [Cache Management](#cache-management)
* [Security Notes](#security-notes)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)

## Features

* **Edge‑level Authentication** – Optional signed URLs with expiration.
* **Range Requests & Partial Responses** – Stream video, large files, and resume interrupted downloads.
* **Advanced Cache Management** – Intelligent caching with TTL control, metrics, and purging.
* **Automatic Path Normalisation** – Protection against directory traversal.
* **Flexible CORS** – Fine‑grained per‑origin allow‑list via environment variable.
* **Prometheus Metrics & Health Check** endpoints.
* **Built with [Hono](https://honojs.dev) on Cloudflare Workers** for minimal cold starts.

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

| Variable                    | Description                                   | Example                                       |
|-----------------------------|-----------------------------------------------|-----------------------------------------------|
| `END_POINT`                 | S3 API endpoint                               | `https://s3.us-west-1.amazonaws.com`          |
| `ACCESS_KEY`                | Access key ID                                 | `AKIAEXAMPLE`                                 |
| `SECRET_KEY`                | Secret access key                             | `wJalrX...`                                   |
| `BUCKET_NAME`               | Bucket to proxy                               | `my-assets`                                   |
| `RANGE_RETRY_ATTEMPTS`      | Max retries for 206 responses                 | `3`                                           |
| `URL_SIGNING_SECRET`        | HMAC secret for signed URLs (omit to disable) | `super‑secret`                                |
| `CORS_ALLOW_ORIGINS`        | Comma‑separated allow‑list                    | `https://example.com,https://app.example.com` |
| `VERSION`                   | Arbitrary version string                      | `v1.0.0`                                      |
| `CACHE_ENABLED`             | Enable caching                                | `true`                                        |
| `CACHE_TTL_SECONDS`         | Cache TTL in seconds                          | `3600`                                        |
| `CACHE_DEBUG`               | Enable debug mode                             | `false`                                       |
| `CACHE_MIN_TTL_SECONDS`     | Minimum cache TTL in seconds                  | `60`                                          |
| `CACHE_MAX_TTL_SECONDS`     | Maximum cache TTL in seconds                  | `86400`                                       |
| `CACHE_OVERRIDE_S3_HEADERS` | Override S3 headers in cache                  | `false`                                       |
| `CACHE_PURGE_SECRET`        | Secret for cache invalidation                 | `your-secure-secret`                          |

Example `wrangler.toml` snippet:

```toml
[vars]
END_POINT = "..."
ACCESS_KEY = "..."
SECRET_KEY = "..."
BUCKET_NAME = "..."
RANGE_RETRY_ATTEMPTS = 3
CORS_ALLOW_ORIGINS = "https://example.com"
VERSION = "v1.0.0"
CACHE_ENABLED = true
CACHE_TTL_SECONDS = 3600
CACHE_DEBUG = false
CACHE_MIN_TTL_SECONDS = 60
CACHE_MAX_TTL_SECONDS = 86400
CACHE_OVERRIDE_S3_HEADERS = false
CACHE_PURGE_SECRET = "your-secure-secret"
```

## API Reference

### `GET /list?prefix=<path/>`

Returns the object keys directly under the given prefix.

```json
{
  "keys": [
    "images/a.jpg",
    "images/b.png"
  ]
}
```

### `GET /<key>[?download[=name]|inline]`

Fetches the object as‑is. Supports HTTP `Range` headers.

* `download` – forces `Content‑Disposition: attachment` (optionally override filename).
* `inline` – forces `Content‑Disposition: inline`.

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

### `POST /<filename>/uploads`

Initiates a multipart upload. Forward `Content-Type` and`x-amz-meta-*` headers as needed. The worker proxies the request to S3 and returns the S3 XML response containing the`UploadId`. If URL signing is enabled, this endpoint can be protected by URL signing.

### `DELETE /<filename>`

Deletes a file. An optional`versionId` query parameter can be included. Returns a 200 OK with a JSON body indicating success. If URL signing is enabled, DELETE requests must be signed.

### `POST /delete`

Batch deletes files.
Request body:

```json
{
  "keys": [
    "path/to/object1.txt",
    "path/to/object2.jpg"
  ],
  "quiet": false
  // Optional: if true, S3 returns success even if some keys fail (default false)
}
```

A maximum of 1000 keys can be specified. The S3 XML response detailing the result for each key is returned (unless`quiet` is `true`). If URL signing is enabled, this endpoint can be protected.

### `GET /__health`

Returns build version and server time. Useful for liveness probes.

### `GET /__metrics`

OpenMetrics‑formatted counters: requests, errors, bytes sent, and cache performance metrics.

### `GET /__cache/stats`

Returns detailed cache statistics including hit rates, configuration, and performance metrics.

```json
{
  "config": {
    "enabled": true,
    "ttlSeconds": 3600,
    "overrideS3Headers": false,
    // ... more config ...
  },
  "metrics": {
    "cacheHits": 1250,
    "cacheMisses": 180,
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

```bash
URL_SIGNING_SECRET=your-secret \
node src/generate_signed_url.js /private/report.pdf 1800 # path + expiry seconds
```

The script prints a time‑limited URL like:

```
https://worker.example.com/private/report.pdf?exp=1710000000&sig=abcdef…
```

## Cache Management

This proxy includes a significantly enhanced cache management system that provides better performance, more control, and comprehensive cache operations. Key features include:

* **Hybrid Caching Strategy**: Combines Cloudflare's edge caching with the Cache API.
* **Enhanced Conditional Request Handling**: ETag and Last-Modified support.
* **Advanced Cache Invalidation & Management**: Selective and pattern-based purging, cache warming.
* **Advanced Analytics & Debugging**: Detailed metrics, debug headers, and real-time statistics.

### Cache Endpoints

* `GET /__cache/stats` – Detailed cache statistics and performance metrics.
* `GET /__cache/health` – Health status of the cache system.
* `POST /__cache/purge` – Authenticated cache invalidation endpoint.
* `POST /__cache/warm` – Authenticated endpoint for proactive cache population.

For complete documentation on configuration, best practices, and troubleshooting, see **[docs/cache-management.md](./docs/cache-management.md)**.

## Security Notes

This proxy implements comprehensive security features for production use, including:

* **Enhanced URL Signature Validation**
* **Path Traversal Protection**
* **Cache Security**
* **Constant-Time Verification**
* **Appropriate Error Codes**
* **CORS Protection**

For complete security documentation, implementation details, and best practices, see **[docs/security.md](./docs/security.md)**.

## Roadmap

* Object upload endpoint
* ETag‑aware caching
* Terraform module for one‑command deploy

## Contributing

Pull requests are welcome! Please open an issue first to discuss major changes.

## License

MIT © 2025 Shogo Ishigami

---

### Contact

Found a bug? Have a question? [Open an issue](https://github.com/nusu-github/cf-workers-s3-proxy/issues) and we'll take
a look.
