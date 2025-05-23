/**
 * HTTP methods supported by the S3 proxy
 */
export enum HttpMethod {
  GET = "GET",
  HEAD = "HEAD",
  PUT = "PUT", // For upload functionality
  POST = "POST", // For multipart upload initiation
  DELETE = "DELETE", // For delete functionality
}

/**
 * S3 object metadata structure
 */
export interface S3ObjectMetadata {
  Key: string
  LastModified: string
  ETag: string
  Size: number
  StorageClass: string
}

/**
 * S3 error response structure
 */
export interface S3Error {
  Code: string
  Message: string
  RequestId?: string
  HostId?: string
}

export interface S3ErrorResponse {
  Error: S3Error
}

/**
 * S3 list response structure (ListObjectsV2)
 */
export interface S3ListResponse {
  ListBucketResult?: {
    IsTruncated?: boolean
    Contents?: Array<S3ObjectMetadata> | S3ObjectMetadata
    NextContinuationToken?: string
    Name?: string
    Prefix?: string
    MaxKeys?: number
    KeyCount?: number
  }
}

/**
 * Enhanced list response structure returned by the proxy
 */
export interface EnhancedListResponse {
  objects: S3ObjectMetadata[]
  isTruncated: boolean
  nextContinuationToken?: string
  prefix: string
  keyCount: number
}
