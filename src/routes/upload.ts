import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
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

const upload = new Hono<{ Bindings: Env }>()

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

// Upload file - PUT /:filename
upload.put("/:filename{.*}", filenameValidator, async (c) => {
  // Ensure environment is validated
  ensureEnvironmentValidated(c.env)

  globalThis.__app_metrics.totalRequests++

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  // Security: Enhanced URL signing enforcement for uploads
  const pathname = `/${filename}`
  if (shouldEnforceUrlSigning(c.env, pathname)) {
    if (!c.env.URL_SIGNING_SECRET) {
      throw new HTTPException(501, {
        message: "URL signing is required but not configured",
      })
    }
    await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
  }

  // Get the request body stream
  const body = c.req.raw.body
  if (!body) {
    throw new HTTPException(400, {
      message: "Request body is required for PUT uploads",
    })
  }

  // Prepare headers for S3 request
  const headers = new Headers()

  // Forward Content-Type if provided
  const contentType = c.req.header("content-type")
  if (contentType) {
    headers.set("Content-Type", contentType)
  }

  // Forward Content-MD5 if provided by client (recommended for integrity)
  const contentMd5 = c.req.header("content-md5")
  if (contentMd5) {
    headers.set("Content-MD5", contentMd5)
  }

  // Forward Content-Length if provided
  const contentLength = c.req.header("content-length")
  if (contentLength) {
    headers.set("Content-Length", contentLength)
  }

  // Forward Content-Encoding if provided
  const contentEncoding = c.req.header("content-encoding")
  if (contentEncoding) {
    headers.set("Content-Encoding", contentEncoding)
  }

  // Forward Cache-Control if provided
  const cacheControl = c.req.header("cache-control")
  if (cacheControl) {
    headers.set("Cache-Control", cacheControl)
  }

  // Forward S3 metadata headers (x-amz-meta-*)
  for (const [name, value] of c.req.raw.headers.entries()) {
    if (name.toLowerCase().startsWith("x-amz-meta-")) {
      headers.set(name, value)
    }
  }

  // Forward S3 checksum headers (x-amz-checksum-*)
  for (const [name, value] of c.req.raw.headers.entries()) {
    if (name.toLowerCase().startsWith("x-amz-checksum-")) {
      headers.set(name, value)
    }
  }

  // Forward S3 server-side encryption headers
  const sseHeaders = [
    "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-context",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
  ]

  for (const headerName of sseHeaders) {
    const headerValue = c.req.header(headerName)
    if (headerValue) {
      headers.set(headerName, headerValue)
    }
  }

  const signer = getAwsClient(c.env)
  const url = `${getS3BaseUrl(c.env)}/${filename}`

  try {
    // Sign the request with the body stream
    const signedRequest = await signer.sign(url, {
      method: HttpMethod.PUT,
      headers: headers,
      body: body, // Stream the body directly
    })

    // Execute the upload request
    const response = await fetch(signedRequest)

    // Track upload metrics
    globalThis.__app_metrics.totalUploads++
    if (contentLength) {
      const uploadSize = Number.parseInt(contentLength, 10)
      if (!Number.isNaN(uploadSize)) {
        globalThis.__app_metrics.bytesSent += uploadSize
        globalThis.__app_metrics.bytesUploaded += uploadSize
      }
    }

    // Return the S3 response directly
    // This preserves all S3 headers like ETag, x-amz-version-id, etc.
    return new Response(response.body, response)
  } catch (error) {
    // Log the error for debugging
    console.error("Upload error:", error)

    // Return appropriate error response
    if (error instanceof Error) {
      throw new HTTPException(502, {
        message: `Upload failed: ${error.message}`,
      })
    }

    throw new HTTPException(502, {
      message: "Upload failed: Unknown error occurred",
    })
  }
})

// Generate presigned upload URL - POST /presigned-upload
upload.post(
  "/presigned-upload",
  zValidator("json", presignedUploadSchema),
  async (c) => {
    // Ensure environment is validated
    ensureEnvironmentValidated(c.env)

    globalThis.__app_metrics.totalRequests++

    // Security: URL signing enforcement for presigned URL generation
    if (shouldEnforceUrlSigning(c.env, "/presigned-upload")) {
      if (!c.env.URL_SIGNING_SECRET) {
        throw new HTTPException(501, {
          message: "URL signing is required but not configured",
        })
      }
      await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
    }

    try {
      const { key, expiresIn, conditions } = c.req.valid("json")

      const signer = getAwsClient(c.env)
      const url = `${getS3BaseUrl(c.env)}/${key}`

      // Prepare headers for presigned URL
      const headers = new Headers()

      // Add conditional headers if specified
      if (conditions.contentType) {
        headers.set("Content-Type", conditions.contentType)
      }
      if (conditions.contentLength) {
        headers.set("Content-Length", conditions.contentLength.toString())
      }
      if (conditions.contentMd5) {
        headers.set("Content-MD5", conditions.contentMd5)
      }

      // Add S3 metadata headers if specified
      if (conditions.metadata) {
        for (const [metaKey, metaValue] of Object.entries(
          conditions.metadata,
        )) {
          headers.set(`x-amz-meta-${metaKey}`, String(metaValue))
        }
      }

      // Calculate expiration timestamp
      const expirationTimestamp = Math.floor(Date.now() / 1000) + expiresIn

      // Generate presigned URL using the helper function
      const presignedUrl = await generatePresignedUrl(
        signer,
        url,
        HttpMethod.PUT,
        headers,
        expiresIn,
      )

      const response = {
        presignedUrl: presignedUrl,
        key: key,
        expiresIn: expiresIn,
        expiresAt: new Date(expirationTimestamp * 1000).toISOString(),
        method: "PUT",
        // Include headers that must be included in the actual request
        requiredHeaders: Object.fromEntries(headers.entries()),
      }

      // Track presigned URL generation
      globalThis.__app_metrics.presignedUrlsGenerated++

      return c.json(response)
    } catch (error) {
      console.error("Presigned URL generation error:", error)

      if (error instanceof HTTPException) {
        throw error
      }

      if (error instanceof Error) {
        throw new HTTPException(500, {
          message: `Failed to generate presigned URL: ${error.message}`,
        })
      }

      throw new HTTPException(500, {
        message: "Failed to generate presigned URL: Unknown error",
      })
    }
  },
)

// Multipart upload initiation - POST /:filename/uploads
upload.post("/:filename{.*}/uploads", filenameValidator, async (c) => {
  // Ensure environment is validated
  ensureEnvironmentValidated(c.env)

  globalThis.__app_metrics.totalRequests++

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  // Security: Enhanced URL signing enforcement
  const pathname = `/${filename}/uploads`
  if (shouldEnforceUrlSigning(c.env, pathname)) {
    if (!c.env.URL_SIGNING_SECRET) {
      throw new HTTPException(501, {
        message: "URL signing is required but not configured",
      })
    }
    await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
  }

  try {
    const signer = getAwsClient(c.env)
    const url = `${getS3BaseUrl(c.env)}/${filename}?uploads`

    // Prepare headers
    const headers = new Headers()

    // Forward Content-Type if provided
    const contentType = c.req.header("content-type")
    if (contentType) {
      headers.set("Content-Type", contentType)
    }

    // Forward S3 metadata headers
    for (const [name, value] of c.req.raw.headers.entries()) {
      if (name.toLowerCase().startsWith("x-amz-meta-")) {
        headers.set(name, value)
      }
    }

    // Sign and execute the multipart upload initiation request
    const signedRequest = await signer.sign(url, {
      method: HttpMethod.POST,
      headers: headers,
    })

    const response = await fetch(signedRequest)

    if (!response.ok) {
      throw new HTTPException(response.status as ContentfulStatusCode, {
        message: `Multipart upload initiation failed: ${response.statusText}`,
      })
    }

    // Return the S3 response (contains UploadId in XML format)
    return new Response(response.body, response)
  } catch (error) {
    console.error("Multipart upload initiation error:", error)

    if (error instanceof HTTPException) {
      throw error
    }

    if (error instanceof Error) {
      throw new HTTPException(502, {
        message: `Multipart upload initiation failed: ${error.message}`,
      })
    }

    throw new HTTPException(502, {
      message: "Multipart upload initiation failed: Unknown error",
    })
  }
})

export default upload
