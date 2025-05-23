import { XMLParser } from "fast-xml-parser"
import { Hono } from "hono"
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

// List objects – GET /list?prefix=&continuationToken=
list.get("/list", async (c) => {
  // Ensure environment is validated (fail-fast behavior)
  ensureEnvironmentValidated(c.env)

  globalThis.__app_metrics.totalRequests++

  // Security: URL signing enforcement for /list endpoint
  if (shouldEnforceUrlSigning(c.env, "/list")) {
    if (!c.env.URL_SIGNING_SECRET) {
      throw new HTTPException(501, {
        message: "URL signing is required but not configured",
      })
    }
    await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
  }

  // Security: Validate and sanitize prefix parameter
  const rawPrefix = c.req.query("prefix") ?? ""
  const prefix = validateAndSanitizePrefix(rawPrefix, c.env)

  // Get continuation token for pagination
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
  if (
    !contentType.includes("xml") &&
    !contentType.includes("application/xml")
  ) {
    console.warn(`Unexpected content-type for S3 list response: ${contentType}`)
  }

  const xmlData = await resp.text()

  // Validate that we have some content
  if (!xmlData || xmlData.trim().length === 0) {
    throw new HTTPException(502, {
      message: "Empty response from S3",
    })
  }

  let parsedXml: S3ListResponse | S3ErrorResponse

  try {
    // Parse XML with error handling
    parsedXml = xmlParser.parse(xmlData)
  } catch (parseError) {
    console.error("XML parsing error:", parseError)
    throw new HTTPException(502, {
      message: `Invalid XML response from S3: ${parseError instanceof Error ? parseError.message : "Unknown parsing error"}`,
    })
  }

  // Check if the response is an S3 error
  if ("Error" in parsedXml && parsedXml.Error) {
    const s3Error = parsedXml.Error
    console.error("S3 returned error:", s3Error)

    // Map common S3 error codes to appropriate HTTP status codes
    let statusCode: ContentfulStatusCode
    switch (s3Error.Code) {
      case "NoSuchBucket":
      case "NoSuchKey":
        statusCode = 404
        break
      case "AccessDenied":
      case "InvalidAccessKeyId":
      case "SignatureDoesNotMatch":
        statusCode = 403
        break
      case "InvalidBucketName":
      case "InvalidArgument":
        statusCode = 400
        break
      case "InternalError":
      case "ServiceUnavailable":
        statusCode = 502
        break
      case "SlowDown":
      case "RequestTimeout":
        statusCode = 503
        break
      default:
        statusCode = 502
    }

    throw new HTTPException(statusCode, {
      message: `S3 Error: ${s3Error.Code} - ${s3Error.Message}`,
    })
  }

  // Validate expected structure
  if (!("ListBucketResult" in parsedXml) || !parsedXml.ListBucketResult) {
    console.error("Unexpected XML structure:", parsedXml)
    throw new HTTPException(502, {
      message: "Unexpected response structure from S3",
    })
  }

  const listResult = parsedXml.ListBucketResult
  let objects: S3ObjectMetadata[] = []
  const contents = listResult.Contents

  if (contents) {
    try {
      if (Array.isArray(contents)) {
        objects = contents
          .map((item: S3ObjectMetadata) => {
            // Validate required fields
            if (!item?.Key) {
              return null
            }

            return {
              Key: item.Key,
              LastModified: item.LastModified || "",
              ETag: item.ETag || "",
              Size: item.Size,
              StorageClass: item.StorageClass || "STANDARD",
            }
          })
          .filter((obj): obj is S3ObjectMetadata => obj !== null)
      } else if (typeof contents === "object" && contents.Key) {
        // Handle case where there's only one item (contents is an object)
        if (contents.Key.length > 0) {
          objects = [
            {
              Key: contents.Key,
              LastModified: contents.LastModified || "",
              ETag: contents.ETag || "",
              Size: contents.Size,
              StorageClass: contents.StorageClass || "STANDARD",
            },
          ]
        }
      }
    } catch (processingError) {
      console.error("Error processing S3 contents:", processingError)
      throw new HTTPException(502, {
        message: "Error processing S3 response data",
      })
    }
  }

  // Construct enhanced response with pagination and metadata
  const response: EnhancedListResponse = {
    objects: objects,
    isTruncated: Boolean(listResult.IsTruncated),
    prefix: prefix,
    keyCount:
      typeof listResult.KeyCount === "number"
        ? listResult.KeyCount
        : objects.length,
  }

  // Include next continuation token if pagination is available
  if (listResult.NextContinuationToken) {
    response.nextContinuationToken = listResult.NextContinuationToken
  }

  // Add debug logging if needed
  if (c.env.CACHE_DEBUG) {
    console.log(
      `S3 list response processed: ${objects.length} objects found, isTruncated: ${response.isTruncated}`,
    )
    if (response.nextContinuationToken) {
      console.log(`Next continuation token: ${response.nextContinuationToken}`)
    }
  }

  return c.json(response)
})

export default list
