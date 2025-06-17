import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
import type { Context } from "hono"
import { HTTPException } from "hono/http-exception"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import { z } from "zod"
import {
  generatePresignedUrl,
  getAwsClient,
  getS3BaseUrl,
} from "../lib/aws-client.js"
import { shouldEnforceUrlSigning, verifySignature } from "../lib/security.js"
import { ensureEnvironmentValidated } from "../lib/validation.js"
import { HttpMethod } from "../types/s3.js"
import { filenameValidator } from "../validators/filename.js"

// ─────────────────────────────────────── Constants ───────────────────────────────────────
const MULTIPART_PART_LIMITS = {
  MIN_PART_NUMBER: 1,
  MAX_PART_NUMBER: 10000,
  MIN_PART_SIZE: 5 * 1024 * 1024, // 5MB minimum (except last part)
  MAX_PARTS: 10000,
  MAX_MULTIPART_UPLOAD_SIZE: 5 * 1024 * 1024 * 1024 * 1024, // 5TB
} as const

const HTTP_STATUS = {
  BAD_REQUEST: 400,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
} as const

// ─────────────────────────────────────── Schemas ───────────────────────────────────────
const presignedUploadSchema = z.object({
  key: z.string().min(1, "Key cannot be empty"),
  expiresIn: z.number().int().min(1).max(604800).optional().default(3600),
  conditions: z
    .object({
      contentType: z.string().optional(),
      contentLength: z.number().int().min(0).optional(),
      contentMd5: z.string().optional(),
      metadata: z.record(z.string()).optional(),
    })
    .optional()
    .default({}),
})

const _completeMultipartUploadSchema = z.object({
  parts: z
    .array(
      z.object({
        partNumber: z
          .number()
          .int()
          .min(MULTIPART_PART_LIMITS.MIN_PART_NUMBER)
          .max(MULTIPART_PART_LIMITS.MAX_PART_NUMBER),
        etag: z.string().min(1, "ETag cannot be empty"),
      }),
    )
    .min(1, "At least one part is required")
    .max(
      MULTIPART_PART_LIMITS.MAX_PARTS,
      `Maximum ${MULTIPART_PART_LIMITS.MAX_PARTS} parts allowed`,
    ),
})

// ─────────────────────────────────────── Auth Helper Functions ───────────────────────────────────────
async function enforceUrlSigning(
  env: Env,
  pathname: string,
  requestUrl: string,
): Promise<void> {
  if (!shouldEnforceUrlSigning(env, pathname)) return

  if (!env.URL_SIGNING_SECRET) {
    throw new HTTPException(HTTP_STATUS.NOT_IMPLEMENTED, {
      message: "URL signing is required but not configured",
    })
  }

  await verifySignature(new URL(requestUrl), env.URL_SIGNING_SECRET)
}

// ─────────────────────────────────────── Validation Helper Functions ───────────────────────────────────────
function validatePartNumber(partNumber: string): number {
  const partNum = Number.parseInt(partNumber, 10)
  const isValidPartNumber =
    !Number.isNaN(partNum) &&
    partNum >= MULTIPART_PART_LIMITS.MIN_PART_NUMBER &&
    partNum <= MULTIPART_PART_LIMITS.MAX_PART_NUMBER

  if (!isValidPartNumber) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: `Invalid part number. Must be between ${MULTIPART_PART_LIMITS.MIN_PART_NUMBER} and ${MULTIPART_PART_LIMITS.MAX_PART_NUMBER}`,
    })
  }

  return partNum
}

function validateRequestBody(
  body: ReadableStream | null,
  context: string,
): ReadableStream {
  if (!body) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: `Request body is required for ${context}`,
    })
  }
  return body
}

function validateUploadId(
  uploadId: string | undefined,
  context: string,
): string {
  if (!uploadId) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: `Invalid request. For ${context}, uploadId is required`,
    })
  }
  return uploadId
}

function validatePartSize(
  contentLength: string | undefined,
  partNumber: number,
  isLastPart = false,
): number {
  if (!contentLength) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: "Content-Length header is required for multipart uploads",
    })
  }

  const size = Number.parseInt(contentLength, 10)
  if (Number.isNaN(size) || size < 0) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: "Invalid Content-Length value",
    })
  }

  // S3 requires minimum 5MB per part (except the last part)
  if (!isLastPart && size < MULTIPART_PART_LIMITS.MIN_PART_SIZE) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: `Part ${partNumber} is too small. Minimum size is ${MULTIPART_PART_LIMITS.MIN_PART_SIZE} bytes (except for the last part)`,
    })
  }

  return size
}

async function validateMultipartCompletionXML(body: ReadableStream): Promise<{
  xml: string
  parsedParts: Array<{ partNumber: number; etag: string }>
}> {
  const reader = body.getReader()
  const chunks: Uint8Array[] = []
  let totalSize = 0
  const maxXmlSize = 1024 * 1024 // 1MB limit for XML

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      totalSize += value.length
      if (totalSize > maxXmlSize) {
        throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
          message: "Multipart completion XML is too large",
        })
      }

      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }

  if (totalSize === 0) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: "Multipart completion request body is required",
    })
  }

  const xmlBuffer = new Uint8Array(totalSize)
  let offset = 0
  for (const chunk of chunks) {
    xmlBuffer.set(chunk, offset)
    offset += chunk.length
  }

  const xml = new TextDecoder().decode(xmlBuffer)

  // Basic XML validation
  if (
    !xml.includes("<CompleteMultipartUpload>") ||
    !xml.includes("</CompleteMultipartUpload>")
  ) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: "Invalid XML format. Expected CompleteMultipartUpload structure",
    })
  }

  // Extract and validate parts
  const parsedParts = parseMultipartCompletionXML(xml)

  return { xml, parsedParts }
}

function parseMultipartCompletionXML(
  xml: string,
): Array<{ partNumber: number; etag: string }> {
  const parts: Array<{ partNumber: number; etag: string }> = []

  // Simple regex-based parsing (more robust than full XML parser for this specific case)
  const partRegex =
    /<Part>\s*<PartNumber>(\d+)<\/PartNumber>\s*<ETag>([^<]+)<\/ETag>\s*<\/Part>/g

  let match: RegExpExecArray | null = null
  // biome-ignore lint/suspicious/noAssignInExpressions: Necessary for regex iteration
  while ((match = partRegex.exec(xml)) !== null) {
    const partNumber = Number.parseInt(match[1], 10)
    const etag = match[2].trim()

    if (
      Number.isNaN(partNumber) ||
      partNumber < MULTIPART_PART_LIMITS.MIN_PART_NUMBER ||
      partNumber > MULTIPART_PART_LIMITS.MAX_PART_NUMBER
    ) {
      throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
        message: `Invalid part number: ${partNumber}`,
      })
    }

    if (!etag) {
      throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
        message: `Missing ETag for part ${partNumber}`,
      })
    }

    // Check for duplicate part numbers
    if (parts.some((p) => p.partNumber === partNumber)) {
      throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
        message: `Duplicate part number: ${partNumber}`,
      })
    }

    parts.push({ partNumber, etag })
  }

  if (parts.length === 0) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: "No valid parts found in completion XML",
    })
  }

  if (parts.length > MULTIPART_PART_LIMITS.MAX_PARTS) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: `Too many parts: ${parts.length}. Maximum allowed: ${MULTIPART_PART_LIMITS.MAX_PARTS}`,
    })
  }

  // Sort parts by part number and validate sequence
  parts.sort((a, b) => a.partNumber - b.partNumber)

  // Validate that part numbers are sequential (1, 2, 3, ...)
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].partNumber !== i + 1) {
      throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
        message: `Part numbers must be sequential starting from 1. Missing part ${i + 1}`,
      })
    }
  }

  return parts
}

// ─────────────────────────────────────── Header Helper Functions ───────────────────────────────────────
function createBasicHeaders(): Headers {
  return new Headers()
}

function addOptionalHeader(
  headers: Headers,
  name: string,
  value?: string,
): void {
  if (value) {
    headers.set(name, value)
  }
}

function createUploadHeaders(
  contentLength?: string,
  contentMd5?: string,
): Headers {
  const headers = createBasicHeaders()
  addOptionalHeader(headers, "Content-Length", contentLength)
  addOptionalHeader(headers, "Content-MD5", contentMd5)
  return headers
}

function createPresignedUrlHeaders(
  conditions: z.infer<typeof presignedUploadSchema>["conditions"],
): Headers {
  const headers = createBasicHeaders()

  addOptionalHeader(headers, "Content-Type", conditions.contentType)
  addOptionalHeader(headers, "Content-MD5", conditions.contentMd5)

  if (conditions.contentLength) {
    headers.set("Content-Length", conditions.contentLength.toString())
  }

  if (conditions.metadata) {
    for (const [metaKey, metaValue] of Object.entries(conditions.metadata)) {
      headers.set(`x-amz-meta-${metaKey}`, String(metaValue))
    }
  }

  return headers
}

function createMultipartHeaders(sourceHeaders: Headers): Headers {
  const headers = createBasicHeaders()

  const contentType = sourceHeaders.get("content-type")
  addOptionalHeader(headers, "Content-Type", contentType ?? undefined)

  // Forward S3 metadata headers
  for (const [name, value] of sourceHeaders.entries()) {
    if (name.toLowerCase().startsWith("x-amz-meta-")) {
      headers.set(name, value)
    }
  }

  return headers
}

function createXmlHeaders(contentLength?: string): Headers {
  const headers = createBasicHeaders()
  headers.set("Content-Type", "application/xml")
  addOptionalHeader(headers, "Content-Length", contentLength)
  return headers
}

function forwardS3Headers(sourceHeaders: Headers): Headers {
  const headers = createBasicHeaders()

  const relevantHeaders = [
    "content-type",
    "content-md5",
    "content-length",
    "content-encoding",
    "cache-control",
    "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-context",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
  ]

  for (const headerName of relevantHeaders) {
    const value = sourceHeaders.get(headerName)
    addOptionalHeader(headers, headerName, value ?? undefined)
  }

  // Forward S3 metadata and checksum headers
  for (const [name, value] of sourceHeaders.entries()) {
    const lowerName = name.toLowerCase()
    if (
      lowerName.startsWith("x-amz-meta-") ||
      lowerName.startsWith("x-amz-checksum-")
    ) {
      headers.set(name, value)
    }
  }

  return headers
}

// ─────────────────────────────────────── URL Helper Functions ───────────────────────────────────────
function buildMultipartUrl(
  baseUrl: string,
  filename: string,
  operation: "uploads" | "completion" | "abort" | "part",
  uploadId?: string,
  partNumber?: string,
): string {
  const encodedFilename = encodeURIComponent(filename)

  switch (operation) {
    case "uploads":
      return `${baseUrl}/${encodedFilename}?uploads`
    case "part":
      if (!uploadId || !partNumber) {
        throw new Error(
          "uploadId and partNumber are required for part upload operations",
        )
      }
      return `${baseUrl}/${encodedFilename}?partNumber=${encodeURIComponent(partNumber)}&uploadId=${encodeURIComponent(uploadId)}`
    case "completion":
    case "abort":
      if (!uploadId) {
        throw new Error("uploadId is required for completion/abort operations")
      }
      return `${baseUrl}/${encodedFilename}?uploadId=${encodeURIComponent(uploadId)}`
    default:
      throw new Error(`Unknown multipart operation: ${operation}`)
  }
}

// ─────────────────────────────────────── Error Helper Functions ───────────────────────────────────────
function handleUploadError(error: unknown, context: string): never {
  console.error(`${context}:`, error)

  if (error instanceof HTTPException) {
    throw error
  }

  const message =
    error instanceof Error ? error.message : "Unknown error occurred"
  throw new HTTPException(HTTP_STATUS.BAD_GATEWAY, {
    message: `${context}: ${message}`,
  })
}

async function handleS3ResponseError(
  response: Response,
  context: string,
): Promise<void> {
  let errorDetails = ""
  try {
    // Clone the response to avoid consuming the body
    const clonedResponse = response.clone()
    errorDetails = await clonedResponse.text()
  } catch (readError) {
    console.error("Failed to read error response:", readError)
  }

  const statusMessage = `${response.status} ${response.statusText}`

  // Log detailed error for debugging
  console.error(`S3 Error - ${context}:`, {
    status: response.status,
    statusText: response.statusText,
    details: errorDetails,
    headers: Object.fromEntries(response.headers.entries()),
  })

  // Sanitize error details for client response (avoid leaking sensitive info)
  const sanitizedDetails =
    errorDetails.length > 500
      ? `${errorDetails.substring(0, 500)}...`
      : errorDetails
  const fullMessage = `${context}: ${statusMessage}${sanitizedDetails ? ` - ${sanitizedDetails}` : ""}`

  throw new HTTPException(response.status as ContentfulStatusCode, {
    message: fullMessage,
  })
}

// ─────────────────────────────────────── Response Helper Functions ───────────────────────────────────────
function createPresignedUrlResponse(
  presignedUrl: string,
  key: string,
  expiresIn: number,
  headers: Headers,
) {
  const expirationTimestamp = Math.floor(Date.now() / 1000) + expiresIn

  return {
    presignedUrl,
    key,
    expiresIn,
    expiresAt: new Date(expirationTimestamp * 1000).toISOString(),
    method: "PUT",
    requiredHeaders: Object.fromEntries(headers.entries()),
  }
}

function createAbortSuccessResponse(filename: string, uploadId: string) {
  return {
    success: true,
    message: `Multipart upload for '${filename}' aborted successfully`,
    uploadId,
    abortedAt: new Date().toISOString(),
  }
}

// ─────────────────────────────────────── Core Upload Functions ───────────────────────────────────────
async function executeSimpleUpload(
  env: Env,
  filename: string,
  body: ReadableStream,
  sourceHeaders: Headers,
): Promise<Response> {
  const signer = getAwsClient(env)
  const url = `${getS3BaseUrl(env)}/${filename}`
  const headers = forwardS3Headers(sourceHeaders)

  const signedRequest = await signer.sign(url, {
    method: HttpMethod.PUT,
    headers,
    body,
  })

  return await fetch(signedRequest)
}

async function executeMultipartUploadPart(
  env: Env,
  filename: string,
  partNumber: string,
  uploadId: string,
  body: ReadableStream,
  contentLength?: string,
  contentMd5?: string,
): Promise<Response> {
  const signer = getAwsClient(env)
  const baseUrl = getS3BaseUrl(env)
  const url = buildMultipartUrl(baseUrl, filename, "part", uploadId, partNumber)
  const headers = createUploadHeaders(contentLength, contentMd5)

  const signedRequest = await signer.sign(url, {
    method: HttpMethod.PUT,
    headers,
    body,
  })

  return await fetch(signedRequest)
}

async function executeMultipartInit(
  env: Env,
  filename: string,
  sourceHeaders: Headers,
): Promise<Response> {
  const signer = getAwsClient(env)
  const baseUrl = getS3BaseUrl(env)
  const url = buildMultipartUrl(baseUrl, filename, "uploads")
  const headers = createMultipartHeaders(sourceHeaders)

  const signedRequest = await signer.sign(url, {
    method: HttpMethod.POST,
    headers,
  })

  return await fetch(signedRequest)
}

async function executeMultipartCompletion(
  env: Env,
  filename: string,
  uploadId: string,
  body: ReadableStream,
  contentLength?: string,
): Promise<Response> {
  const signer = getAwsClient(env)
  const baseUrl = getS3BaseUrl(env)
  const url = buildMultipartUrl(baseUrl, filename, "completion", uploadId)
  const headers = createXmlHeaders(contentLength)

  const signedRequest = await signer.sign(url, {
    method: HttpMethod.POST,
    headers,
    body,
  })

  return await fetch(signedRequest)
}

async function executeMultipartAbort(
  env: Env,
  filename: string,
  uploadId: string,
): Promise<Response> {
  const signer = getAwsClient(env)
  const baseUrl = getS3BaseUrl(env)
  const url = buildMultipartUrl(baseUrl, filename, "abort", uploadId)

  const signedRequest = await signer.sign(url, {
    method: HttpMethod.DELETE,
  })

  return await fetch(signedRequest)
}

// ─────────────────────────────────────── Route Handler Functions ───────────────────────────────────────
async function handleMultipartUploadPart(
  c: Context<{ Bindings: Env }>,
  filename: string,
  partNumber: string,
  uploadId: string,
): Promise<Response> {
  const validatedPartNumber = validatePartNumber(partNumber)
  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)

  const body = validateRequestBody(c.req.raw.body, "part upload")

  // Validate part size (we don't know if it's the last part, so we'll be lenient for now)
  // S3 will ultimately validate this on completion
  const contentLength = c.req.header("content-length")
  if (contentLength) {
    validatePartSize(contentLength, validatedPartNumber, true) // Allow smaller parts for now
  }

  try {
    const response = await executeMultipartUploadPart(
      c.env,
      filename,
      partNumber,
      uploadId,
      body,
      contentLength,
      c.req.header("content-md5"),
    )

    if (!response.ok) {
      await handleS3ResponseError(
        response,
        `Part ${validatedPartNumber} upload failed`,
      )
    }

    return response
  } catch (error) {
    handleUploadError(error, `Part ${validatedPartNumber} upload failed`)
  }
}

async function handleRegularUpload(
  c: Context<{ Bindings: Env }>,
  filename: string,
): Promise<Response> {
  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)
  const body = validateRequestBody(c.req.raw.body, "PUT uploads")

  try {
    const response = await executeSimpleUpload(
      c.env,
      filename,
      body,
      c.req.raw.headers,
    )

    if (!response.ok) {
      await handleS3ResponseError(response, "Upload failed")
    }

    return response
  } catch (error) {
    handleUploadError(error, "Upload failed")
  }
}

// ─────────────────────────────────────── Router Instance ───────────────────────────────────────
const upload = new Hono<{ Bindings: Env }>()

// ─────────────────────────────────────── Route Handlers ───────────────────────────────────────
upload.put("/:filename{.*}", filenameValidator, async (c) => {
  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  const partNumber = c.req.query("partNumber")
  const uploadId = c.req.query("uploadId")

  if (partNumber && uploadId) {
    return handleMultipartUploadPart(c, filename, partNumber, uploadId)
  }

  return handleRegularUpload(c, filename)
})

upload.post(
  "/presigned-upload",
  zValidator("json", presignedUploadSchema),
  async (c) => {
    ensureEnvironmentValidated(c.env)
    await enforceUrlSigning(c.env, "/presigned-upload", c.req.url)

    try {
      const { key, expiresIn, conditions } = c.req.valid("json")

      const signer = getAwsClient(c.env)
      const url = `${getS3BaseUrl(c.env)}/${key}`
      const headers = createPresignedUrlHeaders(conditions)

      const presignedUrl = await generatePresignedUrl(
        signer,
        url,
        HttpMethod.PUT,
        headers,
        expiresIn,
      )

      const response = createPresignedUrlResponse(
        presignedUrl,
        key,
        expiresIn,
        headers,
      )
      return c.json(response)
    } catch (error) {
      handleUploadError(error, "Failed to generate presigned URL")
    }
  },
)

upload.post("/:filename{.*}/uploads", filenameValidator, async (c) => {
  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  await enforceUrlSigning(c.env, `/${filename}/uploads`, c.req.url)

  try {
    const response = await executeMultipartInit(
      c.env,
      filename,
      c.req.raw.headers,
    )

    if (!response.ok) {
      await handleS3ResponseError(
        response,
        "Multipart upload initiation failed",
      )
    }

    return response
  } catch (error) {
    handleUploadError(error, "Multipart upload initiation failed")
  }
})

upload.post("/:filename{.*}", filenameValidator, async (c) => {
  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename
  const uploadId = validateUploadId(
    c.req.query("uploadId"),
    "multipart completion",
  )

  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)
  const body = validateRequestBody(
    c.req.raw.body,
    "completing multipart upload",
  )

  try {
    // Validate and parse the multipart completion XML
    const { xml, parsedParts } = await validateMultipartCompletionXML(body)

    console.log(
      `Completing multipart upload for ${filename} with ${parsedParts.length} parts`,
    )

    // Create a new ReadableStream with the validated XML
    const xmlStream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(xml))
        controller.close()
      },
    })

    const response = await executeMultipartCompletion(
      c.env,
      filename,
      uploadId,
      xmlStream,
      xml.length.toString(),
    )

    if (!response.ok) {
      await handleS3ResponseError(
        response,
        "Multipart upload completion failed",
      )
    }

    return response
  } catch (error) {
    handleUploadError(error, "Multipart upload completion failed")
  }
})

upload.delete("/:filename{.*}", filenameValidator, async (c) => {
  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename
  const uploadId = validateUploadId(c.req.query("uploadId"), "multipart abort")

  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)

  try {
    const response = await executeMultipartAbort(c.env, filename, uploadId)

    if (!response.ok) {
      await handleS3ResponseError(response, "Multipart upload abort failed")
    }

    return c.json(createAbortSuccessResponse(filename, uploadId))
  } catch (error) {
    handleUploadError(error, "Multipart upload abort failed")
  }
})

export default upload
