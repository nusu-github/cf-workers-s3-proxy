import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
import { HTTPException } from "hono/http-exception"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import { z } from "zod"
import { getAwsClient, getS3BaseUrl } from "../lib/aws-client.js"
import { shouldEnforceUrlSigning, verifySignature } from "../lib/security.js"
import { ensureEnvironmentValidated } from "../lib/validation.js"

import { HttpMethod } from "../types/s3.js"
import { filenameValidator } from "../validators/filename.js"

// ─────────────────────────────────────── Constants ───────────────────────────────────────
const HTTP_STATUS = {
  NO_CONTENT: 204,
  BAD_GATEWAY: 502,
  NOT_IMPLEMENTED: 501,
} as const

// ─────────────────────────────────────── Schemas ───────────────────────────────────────
const batchDeleteSchema = z.object({
  keys: z
    .array(z.string().min(1, "Key cannot be empty"))
    .min(1, "Keys array cannot be empty")
    .max(1000, "Maximum 1000 keys allowed")
    .refine((keys) => keys.every((key) => isValidFilename(key)), {
      message:
        "One or more keys contain invalid characters or path traversal attempts",
    }),
  quiet: z.boolean().optional().default(false),
})

// ─────────────────────────────────────── Validation Helper Functions ───────────────────────────────────────
/**
 * Validates filename for security issues like path traversal
 */
function isValidFilename(filename: string): boolean {
  if (!filename || filename.trim() === "") return false

  // Check for path traversal
  if (filename.includes("..") || filename.match(/%2e|%2f/i)) return false

  // Check for Windows-style path separators
  if (filename.includes("\\")) return false

  // Check for absolute paths
  if (filename.startsWith("/")) return false

  // Check for invalid path format
  if (filename.includes("//") || filename.endsWith("/")) return false

  return true
}

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

// ─────────────────────────────────────── Error Helper Functions ───────────────────────────────────────
function handleDeleteError(error: unknown, context: string): never {
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
    errorDetails = await response.clone().text()
  } catch (readError) {
    console.error("Failed to read error response:", readError)
  }

  const statusMessage = `${response.status} ${response.statusText}`
  const fullMessage = `${context}: ${statusMessage}${errorDetails ? ` - ${errorDetails}` : ""}`

  // Ensure status code is valid for HTTPException
  const statusCode =
    response.status >= 400 && response.status <= 599
      ? (response.status as ContentfulStatusCode)
      : (500 as ContentfulStatusCode)

  throw new HTTPException(statusCode, {
    message: fullMessage,
  })
}

// ─────────────────────────────────────── Request Helper Functions ───────────────────────────────────────
function createDeleteHeaders(versionId?: string): Headers {
  const headers = new Headers()
  if (versionId) {
    headers.set("x-amz-version-id", versionId)
  }
  return headers
}

function createBatchDeleteHeaders(xmlPayload: string): Headers {
  const headers = new Headers()
  headers.set("Content-Type", "application/xml")

  const contentLength = new TextEncoder().encode(xmlPayload).length
  headers.set("Content-Length", contentLength.toString())

  return headers
}

async function calculateContentMD5(content: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(content)
  const hashBuffer = await crypto.subtle.digest("MD5", data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return btoa(String.fromCharCode(...hashArray))
}

// ─────────────────────────────────────── XML Helper Functions ───────────────────────────────────────
function escapeXml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;")
}

function createDeleteXmlObject(key: string): string {
  const escapedKey = escapeXml(key)
  return `    <Object><Key>${escapedKey}</Key></Object>`
}

function createBatchDeleteXml(keys: string[], quiet: boolean): string {
  const xmlObjects = keys.map(createDeleteXmlObject).join("\n")

  return `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Quiet>${quiet}</Quiet>
${xmlObjects}
</Delete>`
}

// ─────────────────────────────────────── Response Helper Functions ───────────────────────────────────────
function createDeleteSuccessResponse(filename: string) {
  return {
    success: true,
    message: `File '${filename}' deleted successfully`,
    deletedAt: new Date().toISOString(),
  }
}

function createBatchDeleteSuccessResponse(keyCount: number) {
  return {
    success: true,
    message: `Batch delete initiated for ${keyCount} objects`,
    deletedAt: new Date().toISOString(),
    quiet: true,
  }
}

// ─────────────────────────────────────── Core Delete Functions ───────────────────────────────────────
async function executeSingleDelete(
  env: Env,
  filename: string,
  versionId?: string,
): Promise<Response> {
  const signer = getAwsClient(env)
  const url = `${getS3BaseUrl(env)}/${filename}`
  const headers = createDeleteHeaders(versionId)

  const signedRequest = await signer.sign(url, {
    method: HttpMethod.DELETE,
    headers,
  })

  return await fetch(signedRequest)
}

async function executeBatchDelete(
  env: Env,
  keys: string[],
  quiet: boolean,
): Promise<Response> {
  const signer = getAwsClient(env)
  const url = `${getS3BaseUrl(env)}?delete`

  const xmlPayload = createBatchDeleteXml(keys, quiet)
  const headers = createBatchDeleteHeaders(xmlPayload)

  const contentMD5 = await calculateContentMD5(xmlPayload)
  headers.set("Content-MD5", contentMD5)

  const signedRequest = await signer.sign(url, {
    method: HttpMethod.POST,
    headers,
    body: xmlPayload,
  })

  return await fetch(signedRequest)
}

// ─────────────────────────────────────── Router Instance ───────────────────────────────────────
const deleteRoute = new Hono<{ Bindings: Env }>()

// ─────────────────────────────────────── Route Handlers ───────────────────────────────────────
deleteRoute.delete("/:filename{.*}", filenameValidator, async (c) => {
  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)

  try {
    const versionId = c.req.query("versionId")
    const response = await executeSingleDelete(c.env, filename, versionId)

    if (response.status === HTTP_STATUS.NO_CONTENT) {
      return c.json(createDeleteSuccessResponse(filename))
    }

    if (!response.ok) {
      await handleS3ResponseError(response, "Delete failed")
    }

    // Return raw S3 response for other successful status codes
    return response.clone()
  } catch (error) {
    handleDeleteError(error, "Delete failed")
  }
})

deleteRoute.post(
  "/delete",
  zValidator("json", batchDeleteSchema),
  async (c) => {
    ensureEnvironmentValidated(c.env)
    await enforceUrlSigning(c.env, "/delete", c.req.url)

    try {
      const { keys, quiet } = c.req.valid("json")
      const response = await executeBatchDelete(c.env, keys, quiet)

      if (!response.ok) {
        await handleS3ResponseError(response, "Batch delete failed")
      }

      if (!quiet) {
        // Clone response before reading to avoid double-read issues
        const clonedResponse = response.clone()
        const responseText = await clonedResponse.text()
        return new Response(responseText, {
          status: response.status,
          headers: response.headers,
        })
      }

      return c.json(createBatchDeleteSuccessResponse(keys.length))
    } catch (error) {
      handleDeleteError(error, "Batch delete failed")
    }
  },
)

export default deleteRoute
