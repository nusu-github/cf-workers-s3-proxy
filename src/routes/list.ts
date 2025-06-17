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

// ─────────────────────────────────────── Constants ───────────────────────────────────────
const HTTP_STATUS = {
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
} as const

const S3_ERROR_STATUS_MAP = {
  NoSuchBucket: 404,
  NoSuchKey: 404,
  AccessDenied: 403,
  InvalidAccessKeyId: 403,
  SignatureDoesNotMatch: 403,
  InvalidBucketName: 400,
  InvalidArgument: 400,
  InternalError: 502,
  ServiceUnavailable: 502,
  SlowDown: 503,
  RequestTimeout: 503,
} as const

// ─────────────────────────────────────── Parser Instance ───────────────────────────────────────
const xmlParser = new XMLParser()

// ─────────────────────────────────────── Auth Helper Functions ───────────────────────────────────────
async function enforceUrlSigning(c: Context<{ Bindings: Env }>): Promise<void> {
  if (!shouldEnforceUrlSigning(c.env, "/list")) return

  if (!c.env.URL_SIGNING_SECRET) {
    throw new HTTPException(HTTP_STATUS.NOT_IMPLEMENTED, {
      message: "URL signing is required but not configured",
    })
  }

  await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
}

// ─────────────────────────────────────── Error Helper Functions ───────────────────────────────────────
function mapS3ErrorToHttpStatus(errorCode: string): ContentfulStatusCode {
  return (
    (S3_ERROR_STATUS_MAP as Record<string, ContentfulStatusCode>)[errorCode] ??
    HTTP_STATUS.BAD_GATEWAY
  )
}

function handleS3Error(parsedXml: S3ErrorResponse): never {
  const s3Error = parsedXml.Error
  console.error("S3 returned error:", s3Error)

  const statusCode = mapS3ErrorToHttpStatus(s3Error.Code)
  throw new HTTPException(statusCode, {
    message: `S3 Error: ${s3Error.Code} - ${s3Error.Message}`,
  })
}

// ─────────────────────────────────────── XML Processing Helper Functions ───────────────────────────────────────
function parseXmlResponse(xmlData: string): S3ListResponse | S3ErrorResponse {
  if (!xmlData?.trim()) {
    throw new HTTPException(HTTP_STATUS.BAD_GATEWAY, {
      message: "Empty response from S3",
    })
  }

  try {
    return xmlParser.parse(xmlData)
  } catch (parseError) {
    console.error("XML parsing error:", parseError)
    const message =
      parseError instanceof Error ? parseError.message : "Unknown parsing error"
    throw new HTTPException(HTTP_STATUS.BAD_GATEWAY, {
      message: `Invalid XML response from S3: ${message}`,
    })
  }
}

function validateXmlStructure(
  parsedXml: S3ListResponse | S3ErrorResponse,
): S3ListResponse {
  // Handle S3 errors first
  if ("Error" in parsedXml && parsedXml.Error) {
    handleS3Error(parsedXml)
  }

  // Validate expected structure
  if (!("ListBucketResult" in parsedXml) || !parsedXml.ListBucketResult) {
    console.error("Unexpected XML structure:", parsedXml)
    throw new HTTPException(HTTP_STATUS.BAD_GATEWAY, {
      message: "Unexpected response structure from S3",
    })
  }

  return parsedXml
}

function parseS3Response(xmlData: string): S3ListResponse {
  const parsedXml = parseXmlResponse(xmlData)
  return validateXmlStructure(parsedXml)
}

// ─────────────────────────────────────── Content Processing Helper Functions ───────────────────────────────────────
function createObjectMetadata(item: S3ObjectMetadata): S3ObjectMetadata | null {
  if (!item?.Key) return null

  return {
    Key: item.Key,
    LastModified: item.LastModified || "",
    ETag: item.ETag || "",
    Size: item.Size,
    StorageClass: item.StorageClass || "STANDARD",
  }
}

function processSingleObject(contents: S3ObjectMetadata): S3ObjectMetadata[] {
  if (typeof contents === "object" && contents.Key?.length > 0) {
    const metadata = createObjectMetadata(contents)
    return metadata ? [metadata] : []
  }
  return []
}

function processObjectArray(contents: S3ObjectMetadata[]): S3ObjectMetadata[] {
  return contents
    .map(createObjectMetadata)
    .filter((obj): obj is S3ObjectMetadata => obj !== null)
}

function processS3Contents(
  contents: S3ObjectMetadata | S3ObjectMetadata[] | undefined,
): S3ObjectMetadata[] {
  if (!contents) return []

  try {
    if (Array.isArray(contents)) {
      return processObjectArray(contents)
    }

    return processSingleObject(contents)
  } catch (processingError) {
    console.error("Error processing S3 contents:", processingError)
    throw new HTTPException(HTTP_STATUS.BAD_GATEWAY, {
      message: "Error processing S3 response data",
    })
  }
}

// ─────────────────────────────────────── Response Helper Functions ───────────────────────────────────────
function calculateKeyCount(
  listResult: NonNullable<S3ListResponse["ListBucketResult"]>,
  objectsLength: number,
): number {
  return typeof listResult.KeyCount === "number"
    ? listResult.KeyCount
    : objectsLength
}

function createEnhancedListResponse(
  objects: S3ObjectMetadata[],
  listResult: NonNullable<S3ListResponse["ListBucketResult"]>,
  prefix: string,
): EnhancedListResponse {
  const response: EnhancedListResponse = {
    objects,
    isTruncated: Boolean(listResult.IsTruncated),
    prefix,
    keyCount: calculateKeyCount(listResult, objects.length),
  }

  if (listResult.NextContinuationToken) {
    response.nextContinuationToken = listResult.NextContinuationToken
  }

  return response
}

function logDebugInfo(
  env: Env,
  objectsLength: number,
  isTruncated: boolean,
  nextToken?: string,
): void {
  if (!env.CACHE_DEBUG) return

  console.log(
    `S3 list response processed: ${objectsLength} objects found, isTruncated: ${isTruncated}`,
  )

  if (nextToken) {
    console.log(`Next continuation token: ${nextToken}`)
  }
}

// ─────────────────────────────────────── Request Helper Functions ───────────────────────────────────────
function buildListUrl(
  baseUrl: string,
  prefix: string,
  continuationToken?: string,
): string {
  let listUrl = `${baseUrl}?list-type=2&prefix=${encodeURIComponent(prefix)}`

  if (continuationToken) {
    listUrl += `&continuation-token=${encodeURIComponent(continuationToken)}`
  }

  return listUrl
}

function validateContentType(response: Response): void {
  const contentType = response.headers.get("content-type") || ""

  if (
    !contentType.includes("xml") &&
    !contentType.includes("application/xml")
  ) {
    console.warn(`Unexpected content-type for S3 list response: ${contentType}`)
  }
}

async function executeS3ListRequest(
  env: Env,
  prefix: string,
  continuationToken?: string,
): Promise<string> {
  const signer = getAwsClient(env)
  const baseUrl = getS3BaseUrl(env)
  const listUrl = buildListUrl(baseUrl, prefix, continuationToken)

  const response = await signer
    .sign(listUrl, { method: HttpMethod.GET })
    .then((req) => fetch(req))

  if (!response.ok) {
    throw new HTTPException(response.status as ContentfulStatusCode, {
      message: response.statusText,
    })
  }

  validateContentType(response)
  return await response.text()
}

// ─────────────────────────────────────── Router Instance ───────────────────────────────────────
const list = new Hono<{ Bindings: Env }>()

// ─────────────────────────────────────── Route Handlers ───────────────────────────────────────
list.get("/list", async (c) => {
  ensureEnvironmentValidated(c.env)
  await enforceUrlSigning(c)

  const rawPrefix = c.req.query("prefix") ?? ""
  const prefix = validateAndSanitizePrefix(rawPrefix, c.env)
  const continuationToken = c.req.query("continuationToken")

  try {
    const xmlData = await executeS3ListRequest(c.env, prefix, continuationToken)
    const parsedXml = parseS3Response(xmlData)

    if (!parsedXml.ListBucketResult) {
      throw new HTTPException(HTTP_STATUS.BAD_GATEWAY, {
        message: "Invalid response structure from S3",
      })
    }

    const listResult = parsedXml.ListBucketResult
    const objects = processS3Contents(listResult.Contents)
    const response = createEnhancedListResponse(objects, listResult, prefix)

    logDebugInfo(
      c.env,
      objects.length,
      response.isTruncated,
      response.nextContinuationToken,
    )

    return c.json(response)
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error
    }

    console.error("List operation failed:", error)
    const message = error instanceof Error ? error.message : "Unknown error"
    throw new HTTPException(HTTP_STATUS.BAD_GATEWAY, {
      message: `List operation failed: ${message}`,
    })
  }
})

export default list
