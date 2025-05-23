// Initialize metrics counters on globalThis if they don't exist
export function initializeMetrics(): void {
  if (typeof globalThis.__app_metrics === "undefined") {
    globalThis.__app_metrics = {
      totalRequests: 0,
      totalErrors: 0,
      bytesSent: 0,
      // Cache metrics
      cacheHits: 0,
      cacheMisses: 0,
      cacheStores: 0,
      cacheErrors: 0,
      cacheBytesServed: 0,
      // Conditional request metrics
      notModifiedResponses: 0,
      // Upload/Write operation metrics
      totalUploads: 0,
      totalDeletes: 0,
      bytesUploaded: 0,
      presignedUrlsGenerated: 0,
    }
  }
}

/**
 * Generate Prometheus metrics text
 */
export function generatePrometheusMetrics(): string {
  const metrics = globalThis.__app_metrics
  return [
    "# HELP worker_requests_total Total HTTP requests",
    "# TYPE worker_requests_total counter",
    `worker_requests_total ${metrics.totalRequests}`,
    "# HELP worker_errors_total Total errors",
    "# TYPE worker_errors_total counter",
    `worker_errors_total ${metrics.totalErrors}`,
    "# HELP worker_bytes_sent Bytes sent to clients",
    "# TYPE worker_bytes_sent counter",
    `worker_bytes_sent ${metrics.bytesSent}`,
    "# HELP worker_cache_hits_total Cache hits",
    "# TYPE worker_cache_hits_total counter",
    `worker_cache_hits_total ${metrics.cacheHits}`,
    "# HELP worker_cache_misses_total Cache misses",
    "# TYPE worker_cache_misses_total counter",
    `worker_cache_misses_total ${metrics.cacheMisses}`,
    "# HELP worker_cache_stores_total Cache stores",
    "# TYPE worker_cache_stores_total counter",
    `worker_cache_stores_total ${metrics.cacheStores}`,
    "# HELP worker_cache_errors_total Cache errors",
    "# TYPE worker_cache_errors_total counter",
    `worker_cache_errors_total ${metrics.cacheErrors}`,
    "# HELP worker_cache_bytes_served Bytes served from cache",
    "# TYPE worker_cache_bytes_served counter",
    `worker_cache_bytes_served ${metrics.cacheBytesServed}`,
    "# HELP worker_not_modified_responses_total Not Modified (304) responses",
    "# TYPE worker_not_modified_responses_total counter",
    `worker_not_modified_responses_total ${metrics.notModifiedResponses}`,
    "# HELP worker_uploads_total Total upload operations",
    "# TYPE worker_uploads_total counter",
    `worker_uploads_total ${metrics.totalUploads}`,
    "# HELP worker_deletes_total Total delete operations",
    "# TYPE worker_deletes_total counter",
    `worker_deletes_total ${metrics.totalDeletes}`,
    "# HELP worker_bytes_uploaded Total bytes uploaded",
    "# TYPE worker_bytes_uploaded counter",
    `worker_bytes_uploaded ${metrics.bytesUploaded}`,
    "# HELP worker_presigned_urls_generated_total Total presigned URLs generated",
    "# TYPE worker_presigned_urls_generated_total counter",
    `worker_presigned_urls_generated_total ${metrics.presignedUrlsGenerated}`,
  ].join("\n")
}
