# CF Workers S3 Proxy - Source Code Structure

This document describes the modular structure of the CloudFlare Workers S3 Proxy codebase after refactoring from a
single large file into well-organized modules.

## Directory Structure

```
src/
├── index.ts                 # Main application entry point
├── types/                   # TypeScript type definitions
│   ├── cache.ts            # Cache-related types
│   └── s3.ts               # S3-related types and enums
├── lib/                     # Core library functions
│   ├── aws-client.ts       # AWS client management, S3 fetch, presigned URL generation
│   ├── cache.ts            # Caching functionality
│   ├── metrics.ts          # Metrics collection
│   ├── security.ts         # Security and validation
│   ├── utils.ts            # Utility functions
│   └── validation.ts       # Environment validation
├── middleware/              # Middleware setup
│   ├── setup.ts            # CORS, logging, security headers, timing, ETag, compression
├── routes/                  # Route handlers
│   ├── health.ts           # Health check endpoints
│   ├── metrics.ts          # Metrics endpoints
│   ├── list.ts             # S3 list operations
│   ├── files.ts            # File GET/HEAD operations
│   ├── upload.ts           # Upload operations (PUT, presigned URLs, multipart initiation)
│   └── delete.ts           # Delete operations (single and batch DELETE)
└── validators/              # Request validators
    └── filename.ts         # Filename validation
```

## Module Descriptions

### Types (`types/`)

**cache.ts**

- `CacheConfig` interface for cache configuration
- `CacheResult` interface for cache operation results
- `CfProperties` for CloudFlare-specific fetch options

**metrics.ts**

- `AppMetrics` interface for application metrics, including upload/delete counters
- Global metrics declaration

**s3.ts**

- `HttpMethod` enum for supported HTTP methods (GET, HEAD, PUT, POST, DELETE)
- S3 error response interfaces
- S3 list response interfaces

### Core Libraries (`lib/`)

**aws-client.ts**

- AWS client singleton management
- S3 URL construction helpers
- S3 fetch operations with retry logic (GET, HEAD, PUT, DELETE, POST)
- Presigned URL generation for S3 operations (e.g., PUT uploads)

**cache.ts**

- Cache configuration parsing
- Cache key generation (security-aware)
- TTL calculation from response headers
- Intelligent caching with CloudFlare Workers
- Cache hit/miss tracking

**metrics.ts**

- Metrics initialization
- Prometheus metrics generation (including upload/delete metrics)
- Metrics collection helpers

**security.ts**

- URL signature verification (AWS Signature V4)
- Prefix validation and sanitization
- URL signing enforcement logic

**utils.ts**

- Integer parsing utility
- RFC3986 encoding for query parameters
- Canonical query string creation
- Filename sanitization

**validation.ts**

- Comprehensive environment validation
- Fail-fast configuration checking
- Single-run validation enforcement

### Middleware (`middleware/`)

**setup.ts**

- Security headers configuration
- CORS setup with environment-based origins
- Request ID and logging middleware
- Metrics tracking middleware

### Route Handlers (`routes/`)

**health.ts**

- Root route (404)
- Health check endpoint (`/__health`)

**metrics.ts**

- Prometheus metrics endpoint (`/__metrics`) including write operation metrics
- Cache statistics endpoint (`/__cache/stats`)

**cache.ts**

- Cache purging endpoint (`/__cache/purge`)

**list.ts**

- S3 object listing (`/list?prefix=`)
- Comprehensive error handling
- XML response parsing

**files.ts**

- File serving (GET/HEAD operations)
- Range request support
- Conditional request handling
- Download/inline disposition

**upload.ts**

- Direct file upload operations (PUT) with streaming support.
- Presigned URL generation for client-side uploads (POST `/presigned-upload`).
- Multipart upload initiation (POST `/:filename/uploads`).

**delete.ts**

- Single file deletion operations (DELETE `/:filename`).
- Batch file deletion operations (POST `/delete`).

### Validators (`validators/`)

**filename.ts**

- Hono validator for filename parameters
- Path traversal prevention
- Filename normalization

## Hono Framework Features Utilized

### Core Middleware Features

**Enhanced Middleware Stack (`middleware/setup.ts`):**

- **Timing Middleware**: Performance monitoring with `timing()` middleware
- **ETag Middleware**: Automatic ETag generation for cacheable responses using `etag()`
- **Body Limit Middleware**: Request size limiting with `bodyLimit()` for different endpoints
- **Compression Middleware**: Response compression with `compress()` (when available)
- **Enhanced CORS**: Comprehensive CORS configuration with multiple headers and methods
- **Request ID**: Automatic request ID generation with `requestId()`
- **Secure Headers**: Enhanced security headers with `secureHeaders()`
- **Custom Rate Limiting**: Simple rate limiting implementation using context variables

### Routing and Organization Features

**Route Grouping and Organization:**

- **API Route Groups**: Organized routes into logical groups for better structure
- **Middleware Scoping**: Applied specific middleware only to relevant routes
- **Route-specific Body Limits**: Different size limits for different endpoints
- **Method-specific Handlers**: Separate handling for GET, HEAD, PUT, POST, DELETE

**Advanced Route Features:**

- **Path Parameter Validation**: Enhanced filename validation with `filenameValidator`
- **Zod Integration**: Request body validation using `@hono/zod-validator`
- **Pattern Matching**: Advanced path patterns for file serving

### Request/Response Handling

**Enhanced Request Processing:**

- **Stream Handling**: Better support for streaming uploads and downloads
- **Header Validation**: Comprehensive header validation and forwarding
- **Context Variables**: Request context management for debugging and metrics
- **Content Disposition**: Smart filename handling for downloads

**Response Enhancement:**

- **Custom Headers**: Debug headers and performance timing
- **Error Context**: Enhanced error responses with request IDs and timestamps
- **Status Code Mapping**: Proper HTTP status codes for different scenarios

### Validation and Security

**Request Validation:**

- **Zod Schemas**: Type-safe request validation using Zod
- **Custom Validators**: Reusable validation middleware
- **Header Validation**: Content-Type, Content-Length, and other header validation

**Security Features:**

- **Input Sanitization**: Comprehensive input validation and sanitization
- **CORS Security**: Fine-grained CORS controls
- **Rate Limiting**: Protection against abuse

### Performance Optimizations

**Caching Integration:**

- **ETag Support**: Automatic ETag generation for better caching
- **Conditional Requests**: Support for If-None-Match and If-Modified-Since
- **Cache-aware Responses**: Proper cache headers and validation

**Streaming and Memory:**

- **Body Streaming**: Direct streaming for uploads and downloads
- **Memory Management**: Efficient handling of large files
- **Response Optimization**: Minimal response copying

### Error Handling and Debugging

**Enhanced Error Handling:**

- **Context-aware Errors**: Errors include request context and timing
- **Structured Logging**: Comprehensive error logging with metadata
- **Custom Error Types**: Different error types for different scenarios

**Development Features:**

- **Debug Headers**: Optional debug information in responses
- **Performance Timing**: Request timing information
- **Comprehensive Logging**: Enhanced logging with timestamps and request IDs

### Environment and Configuration

**Environment Validation:**

- **Fail-fast Validation**: Environment validation middleware
- **Type-safe Config**: Comprehensive environment variable validation
- **Lazy Loading**: Dynamic middleware loading based on configuration

## Benefits of Hono Feature Usage

### 1. **Performance Improvements**

- **Timing Middleware**: Real-time performance monitoring
- **ETag Support**: Reduced bandwidth usage through proper caching
- **Streaming**: Memory-efficient handling of large files
- **Compression**: Reduced response sizes where applicable

### 2. **Security Enhancements**

- **Enhanced CORS**: Better cross-origin security
- **Input Validation**: Comprehensive request validation
- **Rate Limiting**: Protection against abuse

### 3. **Developer Experience**

- **Type Safety**: Strong TypeScript integration
- **Error Context**: Better debugging information
- **Middleware Composition**: Reusable middleware components
- **Route Organization**: Clear separation of concerns

### 4. **Operational Excellence**

- **Request Tracing**: Request IDs for tracking
- **Performance Metrics**: Built-in timing information
- **Comprehensive Logging**: Enhanced logging capabilities
- **Health Monitoring**: Better observability

### 5. **Maintainability**

- **Modular Architecture**: Well-organized code structure
- **Reusable Components**: Middleware and validation reuse
- **Clear Separation**: API vs. file serving separation
- **Configuration Management**: Environment-based configuration

## Advanced Features Demonstrated

### Context Management

```typescript
// Request context for debugging and metrics
c.set("operation", "file-get");
c.set("filename", filename);
c.set("rangeRequest", true);
```

### Multi-method Authentication

```typescript
// Flexible authentication supporting multiple methods
multiAuthMiddleware(["bearer", "jwt", "url-signing", "api-key"])
```

### Route-specific Middleware

```typescript
// Different body limits for different endpoints
app.use("/presigned-upload", setupBodyLimit(1024));
app.use("/:filename{.*}/uploads", setupBodyLimit(1024));
```

### Enhanced Error Handling

```typescript
// Context-aware error responses
return c.json({ 
    error: message,
    requestId,
    timestamp: new Date().toISOString(),
}, status);
```

This implementation showcases how to effectively leverage Hono's powerful features to build a production-ready,
high-performance S3 proxy service with comprehensive security, monitoring, and developer experience features.

## Key Benefits of This Structure

### 1. **Separation of Concerns**

- Each module has a single, well-defined responsibility
- Clear boundaries between different functionalities
- Easier to understand and maintain

### 2. **Testability**

- Individual modules can be unit tested in isolation
- Mock dependencies for focused testing
- Clear interfaces between components

### 3. **Extensibility**

- Easy to add new functionality
- New route handlers can be added without touching core logic
- Middleware can be composed and reused

### 4. **Type Safety**

- Strong TypeScript types throughout
- Shared type definitions prevent inconsistencies
- Compile-time error catching

### 5. **Security**

- Centralized security logic in dedicated modules
- Consistent validation across all routes
- Clear separation of authentication/authorization

## Write Operations (PUT/DELETE)

The proxy now supports uploading (PUT) and deleting (DELETE) objects in S3.

### Direct Upload (PUT `/:filename`)

- **Streaming Support:** Files can be uploaded by making a PUT request to `/:filename`. The worker streams the request
  body directly to S3.
- **Header Forwarding:** Relevant headers like `Content-Type`, `Content-MD5`, `Content-Length`, `Content-Encoding`,
  `Cache-Control`, `x-amz-meta-*`, `x-amz-checksum-*`, and S3 server-side encryption headers are forwarded to S3.
- **URL Signing:** If `URL_SIGNING_SECRET` is configured and `ENFORCE_URL_SIGNING` is true or the path is listed in
  `URL_SIGNING_REQUIRED_PATHS`, PUT requests must be signed.

### Presigned URLs for Uploads (POST `/presigned-upload`)

To offload data transfer from the proxy, the worker can generate a presigned S3 URL for PUT uploads.

- **Request:** Send a POST request to `/presigned-upload` with a JSON body:

  ```json
  {
    "key": "path/to/your/object.txt",
    "expiresIn": 3600, // Optional: expiration in seconds (default 3600, max 7 days)
    "conditions": { // Optional: conditions for the upload
      "contentType": "text/plain",
      "contentLength": 1024, // in bytes
      "contentMd5": "base64-md5-hash",
      "metadata": {
        "custom-key": "custom-value"
      }
    }
  }
  ```

- **Response:** The worker returns a JSON object containing the `presignedUrl`, `key`, `expiresIn`, `expiresAt`,
  `method` ("PUT"), and `requiredHeaders` that the client must include when making the PUT request to the presigned URL.
- **URL Signing (for this endpoint):** If configured, the `/presigned-upload` endpoint itself can be protected by URL
  signing.

### Multipart Upload Initiation (POST `/:filename/uploads`)

For large files, multipart uploads can be initiated.

- **Request:** Send a POST request to `/:filename/uploads`. Forward `Content-Type` and `x-amz-meta-*` headers as needed.
- **Response:** The worker proxies the request to S3 and returns the S3 XML response containing the `UploadId`.
- **URL Signing:** If configured, this endpoint can be protected by URL signing.
- **Note:** This only initiates the multipart upload. Subsequent `UploadPart` and `CompleteMultipartUpload` operations
  would typically be done directly to S3 using presigned URLs for each part (not currently implemented by this proxy but
  can be added).

### Single File Deletion (DELETE `/:filename`)

- **Request:** Send a DELETE request to `/:filename`. An optional `versionId` query parameter can be included for
  deleting specific versions of an object.
- **Response:** On successful deletion (or if the object doesn't exist), a 200 OK with a JSON body indicating success is
  returned. Otherwise, an appropriate S3 error is proxied.
- **URL Signing:** If configured, DELETE requests must be signed.

### Batch File Deletion (POST `/delete`)

- **Request:** Send a POST request to `/delete` with a JSON body:

  ```json
  {
    "keys": ["path/to/object1.txt", "path/to/object2.jpg"],
    "quiet": false // Optional: if true, S3 returns success even if some keys fail (default false)
  }
  ```

  A maximum of 1000 keys can be specified.
- **Response:**
    - If `quiet` is `false` (or omitted): The S3 XML response detailing the result for each key is returned.
    - If `quiet` is `true`: A 200 OK with a JSON body indicating success is returned.
- **Content-MD5:** The proxy calculates and includes the `Content-MD5` header for the XML payload sent to S3.
- **URL Signing:** If configured, this endpoint can be protected by URL signing.

## Adding New Functionality

### Adding Upload Operations

To implement upload functionality in `routes/upload.ts`:

1. Import necessary types and utilities
2. Add authentication/authorization checks
3. Implement file validation (size, type, etc.)
4. Handle multipart uploads for large files
5. Add proper error handling and metrics
6. Update the main `index.ts` if needed

### Adding Delete Operations

To implement delete functionality in `routes/delete.ts`:

1. Add security checks (delete permissions)
2. Implement single file deletion
3. Add batch delete operations
4. Handle S3 error responses
5. Add audit logging for delete operations

### Adding New Routes

1. Create new route handler in `routes/`
2. Import necessary dependencies
3. Implement route logic with proper error handling
4. Add route to main `index.ts` using `app.route()`
5. Update relevant documentation, including this README

## Development Guidelines

### Imports

- Use relative imports with `.js` extensions for proper ES module compatibility
- Import types using `import type` for better tree-shaking
- Group imports: types first, then modules

### Error Handling

- Use `HTTPException` from Hono for HTTP errors
- Provide meaningful error messages
- Log errors appropriately for debugging

### Security

- Always validate and sanitize inputs
- Use existing security utilities
- Follow principle of the least privilege
- Document security considerations

### Performance

- Use caching where appropriate
- Minimize redundant operations
- Leverage CloudFlare Workers optimizations
- Monitor metrics for performance issues

## Future Improvements

1. **Testing Framework**: Add comprehensive unit and integration tests
2. **Documentation**: Add JSDoc comments for better IDE support
3. **Configuration**: Add runtime configuration validation
4. **Monitoring**: Enhanced metrics and alerting
5. **Security**: Additional security headers and validation
6. **Performance**: Further caching optimizations
