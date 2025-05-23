import { XMLParser } from "fast-xml-parser"
import { Hono } from "hono"
import type { Context } from "hono"
import { HTTPException } from "hono/http-exception"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import { getAwsClient, getS3BaseUrl } from "../lib/aws-client.js"
import {
  shouldEnforceUrlSigning,
  validateAndSanitizePrefix,
  verifySignature,
} from "../lib/security.js"
import { ensureEnvironmentValidated } from "../lib/validation.js"

import type {
  EnhancedListResponse,
  S3ErrorResponse,
  S3ListResponse,
  S3ObjectMetadata,
} from "../types/s3.js"
import { HttpMethod } from "../types/s3.js"

const xmlParser = new XMLParser()
const list = new Hono<{ Bindings: Env }>()

/**
 * Validates URL signing for list endpoint
 */
async function validateListAccess(c: Context<{ Bindings: Env }>): Promise<void> {
  if (shouldEnforceUrlSigning(c.env, "/list")) {
    if (!c.env.URL_SIGNING_SECRET) {
      throw new HTTPException(501, {
        message: "URL signing is required but not configured",
      })
    }
    await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
  }
}

/**
 * Maps S3 error codes to HTTP status codes
 */
function mapS3ErrorToHttpStatus(errorCode: string): ContentfulStatusCode {
  switch (errorCode) {
    case "NoSuchBucket":
    case "NoSuchKey":
      return 404
    case "AccessDenied":
    case "InvalidAccessKeyId":
    case "SignatureDoesNotMatch":
      return 403
    case "InvalidBucketName":
    case "InvalidArgument":
      return 400
    case "InternalError":
    case "ServiceUnavailable":
      return 502
    case "SlowDown":
    case "RequestTimeout":
      return 503
    default:
      return 502
  }
}

/**
 * Handles S3 error responses
 */
function handleS3Error(parsedXml: S3ErrorResponse): never {
  const s3Error = parsedXml.Error
  console.error("S3 returned error:", s3Error)
  
  const statusCode = mapS3ErrorToHttpStatus(s3Error.Code)
  throw new HTTPException(statusCode, {
    message: `S3 Error: ${s3Error.Code} - ${s3Error.Message}`,
  })
}

/**
 * Processes S3 contents into standardized object metadata
 */
function processS3Contents(contents: S3ObjectMetadata | S3ObjectMetadata[] | undefined): S3ObjectMetadata[] {
  if (!contents) return []

  try {
    if (Array.isArray(contents)) {
      return contents
        .map((item: S3ObjectMetadata) => {
          if (!item?.Key) return null
          return {
            Key: item.Key,
            LastModified: item.LastModified || "",
            ETag: item.ETag || "",
            Size: item.Size,
            StorageClass: item.StorageClass || "STANDARD",
          }
        })
        .filter((obj): obj is S3ObjectMetadata => obj !== null)
    } 
    
    if (typeof contents === "object" && contents.Key?.length > 0) {
      return [{
        Key: contents.Key,
        LastModified: contents.LastModified || "",
        ETag: contents.ETag || "",
        Size: contents.Size,
        StorageClass: contents.StorageClass || "STANDARD",
      }]
    }
    
    return []
  } catch (processingError) {
    console.error("Error processing S3 contents:", processingError)
    throw new HTTPException(502, {
      message: "Error processing S3 response data",
    })
  }
}

/**
 * Parses and validates S3 XML response
 */
function parseS3Response(xmlData: string): S3ListResponse {
  if (!xmlData?.trim()) {
    throw new HTTPException(502, { message: "Empty response from S3" })
  }

  let parsedXml: S3ListResponse | S3ErrorResponse
  try {
    parsedXml = xmlParser.parse(xmlData)
  } catch (parseError) {
    console.error("XML parsing error:", parseError)
    throw new HTTPException(502, {
      message: `Invalid XML response from S3: ${parseError instanceof Error ? parseError.message : "Unknown parsing error"}`,
    })
  }

  // Handle S3 errors
  if ("Error" in parsedXml && parsedXml.Error) {
    handleS3Error(parsedXml)
  }

  // Validate expected structure
  if (!("ListBucketResult" in parsedXml) || !parsedXml.ListBucketResult) {
    console.error("Unexpected XML structure:", parsedXml)
    throw new HTTPException(502, {
      message: "Unexpected response structure from S3",
    })
  }

  return parsedXml
}

// List objects – GET /list?prefix=&continuationToken=
list.get("/list", async (c) => {
  ensureEnvironmentValidated(c.env)
  globalThis.__app_metrics.totalRequests++

  await validateListAccess(c)

  // Security: Validate and sanitize prefix parameter
  const rawPrefix = c.req.query("prefix") ?? ""
  const prefix = validateAndSanitizePrefix(rawPrefix, c.env)
  const continuationToken = c.req.query("continuationToken")

  const signer = getAwsClient(c.env)

  // Build S3 API URL with pagination support
  let listUrl = `${getS3BaseUrl(c.env)}?list-type=2&prefix=${encodeURIComponent(prefix)}`
  if (continuationToken) {
    listUrl += `&continuation-token=${encodeURIComponent(continuationToken)}`
  }

  const resp = await signer
    .sign(listUrl, { method: HttpMethod.GET })
    .then((req) => fetch(req))

  if (!resp.ok) {
    throw new HTTPException(resp.status as ContentfulStatusCode, {
      message: resp.statusText,
    })
  }

  // Validate content type
  const contentType = resp.headers.get("content-type") || ""
  if (!contentType.includes("xml") && !contentType.includes("application/xml")) {
    console.warn(`Unexpected content-type for S3 list response: ${contentType}`)
  }

  const xmlData = await resp.text()
  const parsedXml = parseS3Response(xmlData)
  
  if (!parsedXml.ListBucketResult) {
    throw new HTTPException(502, {
      message: "Invalid response structure from S3",
    })
  }
  
  const listResult = parsedXml.ListBucketResult
  const objects = processS3Contents(listResult.Contents)

  // Construct enhanced response with pagination and metadata
  const response: EnhancedListResponse = {
    objects: objects,
    isTruncated: Boolean(listResult.IsTruncated),
    prefix: prefix,
    keyCount: typeof listResult.KeyCount === "number" ? listResult.KeyCount : objects.length,
  }

  // Include next continuation token if pagination is available
  if (listResult.NextContinuationToken) {
    response.nextContinuationToken = listResult.NextContinuationToken
  }

  // Add debug logging if needed
  if (c.env.CACHE_DEBUG) {
    console.log(`S3 list response processed: ${objects.length} objects found, isTruncated: ${response.isTruncated}`)
    if (response.nextContinuationToken) {
      console.log(`Next continuation token: ${response.nextContinuationToken}`)
    }
  }

  return c.json(response)
})

export default list
