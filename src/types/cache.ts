/**
 * Cache configuration options
 */
export interface CacheConfig {
  enabled: boolean
  ttlSeconds: number
  overrideS3Headers: boolean
  minTtlSeconds: number
  maxTtlSeconds: number
  debug: boolean
}

/**
 * Cache operation result
 */
export interface CacheResult {
  hit: boolean
  ttl?: number | undefined
  source: "cache" | "s3" | "error"
  key?: string
}

/**
 * CloudFlare Workers fetch cf options interface
 */
export interface CfProperties {
  cacheKey?: string
  cacheTtl?: number
  cacheEverything?: boolean
}
