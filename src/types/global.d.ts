declare global {
  interface AppMetrics {
    notModifiedResponses: number
    cacheHits: number
    cacheBytesServed: number
    cacheErrors: number
    cacheMisses: number
    bytesSent: number
    cacheStores: number
    totalErrors: number
    totalRequests: number
    totalDeletes: number
    totalUploads: number
    bytesUploaded: number
    presignedUrlsGenerated: number
  }

  // eslint-disable-next-line no-var
  var __app_metrics: AppMetrics
}

// This is necessary to make the file a module, do not remove
export {}
