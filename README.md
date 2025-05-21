# Cloudflare Workers S3 Proxy

![Cloudflare Workers](https://img.shields.io/badge/cloudflare%20workers-F38020?style=for-the-badge\&logo=cloudflare) ![Hono](https://img.shields.io/badge/hono-E36002?style=for-the-badge\&logo=hono) ![MIT License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

A lightweight, cache‑friendly proxy that lets you serve objects from any S3‑compatible storage (Backblaze B2, MinIO,
DigitalOcean Spaces, etc.) through the Cloudflare edge. Perfect for static asset hosting, private downloads, or as a
drop‑in CDN for existing buckets.

## Table of Contents

* [Features](#features)
* [Quick Start](#quick-start)
* [Deployment](#deployment)
* [Configuration](#configuration)
* [API Reference](#api-reference)
* [Signed URLs](#signed-urls)
* [Security Notes](#security-notes)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)

## Features

* **Edge‑level Authentication** – Optional signed URLs with expiration.
* **Range Requests & Partial Responses** – Stream video, large files, and resume interrupted downloads.
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

| Variable               | Description                                   | Example                                       |
|------------------------|-----------------------------------------------|-----------------------------------------------|
| `END_POINT`            | S3 API endpoint                               | `https://s3.us-west-1.amazonaws.com`          |
| `ACCESS_KEY`           | Access key ID                                 | `AKIAEXAMPLE`                                 |
| `SECRET_KEY`           | Secret access key                             | `wJalrX...`                                   |
| `BUCKET_NAME`          | Bucket to proxy                               | `my-assets`                                   |
| `RANGE_RETRY_ATTEMPTS` | Max retries for 206 responses                 | `3`                                           |
| `URL_SIGNING_SECRET`   | HMAC secret for signed URLs (omit to disable) | `super‑secret`                                |
| `CORS_ALLOW_ORIGINS`   | Comma‑separated allow‑list                    | `https://example.com,https://app.example.com` |
| `VERSION`              | Arbitrary version string                      | `v1.0.0`                                      |

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

### `GET /__health`

Returns build version and server time. Useful for liveness probes.

### `GET /__metrics`

OpenMetrics‑formatted counters: requests, errors, bytes sent.

## Signed URLs

```bash
URL_SIGNING_SECRET=your-secret \
node src/generate_signed_url.js /private/report.pdf 1800 # path + expiry seconds
```

The script prints a time‑limited URL like:

```
https://worker.example.com/private/report.pdf?exp=1710000000&sig=abcdef…
```

## Security Notes

* Paths are normalised to prevent traversal attacks.
* Signed URLs are verified with constant‑time comparison.
* CORS headers are added only for whitelisted origins.

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
