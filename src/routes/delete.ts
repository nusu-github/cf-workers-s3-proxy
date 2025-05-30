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

const deleteRoute = new Hono<{ Bindings: Env }>()

const batchDeleteSchema = z.object({
  keys: z
    .array(z.string().min(1, "Key cannot be empty"))
    .min(1, "Keys array cannot be empty")
    .max(1000, "Maximum 1000 keys allowed"),
  quiet: z.boolean().optional().default(false),
})

// Delete file - DELETE /:filename
deleteRoute.delete("/:filename{.*}", filenameValidator, async (c) => {
  // Ensure environment is validated
  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  // Security: Enhanced URL signing enforcement for deletions
  const pathname = `/${filename}`
  if (shouldEnforceUrlSigning(c.env, pathname)) {
    if (!c.env.URL_SIGNING_SECRET) {
      throw new HTTPException(501, {
        message: "URL signing is required but not configured",
      })
    }
    await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
  }

  const signer = getAwsClient(c.env)
  const url = `${getS3BaseUrl(c.env)}/${filename}`

  try {
    // Prepare headers for the delete request
    const headers = new Headers()

    // Forward version ID if provided (for versioned objects)
    const versionId = c.req.query("versionId")
    if (versionId) {
      headers.set("x-amz-version-id", versionId)
    }

    // Sign and execute the delete request
    const signedRequest = await signer.sign(url, {
      method: HttpMethod.DELETE,
      headers: headers,
    })

    const response = await fetch(signedRequest)

    // S3 returns 204 No Content for successful deletions
    // It also returns 204 if the object doesn't exist (idempotent)
    if (response.status === 204) {
      return c.json({
        success: true,
        message: `File '${filename}' deleted successfully`,
        deletedAt: new Date().toISOString(),
      })
    }

    // Handle other response codes
    if (!response.ok) {
      const errorText = await response.text()
      throw new HTTPException(response.status as ContentfulStatusCode, {
        message: `Delete failed: ${response.statusText} - ${errorText}`,
      })
    }

    // Return the raw S3 response for any other successful status
    // Clone the response to avoid body consumption issues
    return response.clone()
  } catch (error) {
    console.error("Delete error:", error)

    if (error instanceof HTTPException) {
      throw error
    }

    if (error instanceof Error) {
      throw new HTTPException(502, {
        message: `Delete failed: ${error.message}`,
      })
    }

    throw new HTTPException(502, {
      message: "Delete failed: Unknown error occurred",
    })
  }
})

// Batch delete - POST /delete
deleteRoute.post(
  "/delete",
  zValidator("json", batchDeleteSchema),
  async (c) => {
    // Ensure environment is validated
    ensureEnvironmentValidated(c.env)

    // Security: URL signing enforcement for batch delete
    if (shouldEnforceUrlSigning(c.env, "/delete")) {
      if (!c.env.URL_SIGNING_SECRET) {
        throw new HTTPException(501, {
          message: "URL signing is required but not configured",
        })
      }
      await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
    }

    try {
      const { keys, quiet } = c.req.valid("json")

      const signer = getAwsClient(c.env)
      const url = `${getS3BaseUrl(c.env)}?delete`

      // Build the S3 batch delete XML payload
      const xmlObjects = keys
        .map((key: string) => {
          // Escape XML characters in the key
          const escapedKey = key
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&apos;")

          return `    <Object><Key>${escapedKey}</Key></Object>`
        })
        .join("\n")

      const xmlPayload = `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Quiet>${quiet}</Quiet>
${xmlObjects}
</Delete>`

      // Prepare headers
      const headers = new Headers()
      headers.set("Content-Type", "application/xml")
      headers.set(
        "Content-Length",
        new TextEncoder().encode(xmlPayload).length.toString(),
      )

      // Calculate Content-MD5 for data integrity
      const encoder = new TextEncoder()
      const data = encoder.encode(xmlPayload)
      const hashBuffer = await crypto.subtle.digest("MD5", data)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const hashBase64 = btoa(String.fromCharCode(...hashArray))
      headers.set("Content-MD5", hashBase64)

      // Sign and execute the batch delete request
      const signedRequest = await signer.sign(url, {
        method: HttpMethod.POST,
        headers: headers,
        body: xmlPayload,
      })

      const response = await fetch(signedRequest)

      if (!response.ok) {
        const errorText = await response.text()
        throw new HTTPException(response.status as ContentfulStatusCode, {
          message: `Batch delete failed: ${response.statusText} - ${errorText}`,
        })
      }

      // Parse the response if not in quiet mode
      if (!quiet) {
        // Clone response before reading body to avoid consumption issues
        const responseClone = response.clone()
        const responseText = await responseClone.text()
        return new Response(responseText, {
          status: response.status,
          headers: response.headers,
        })
      }

      // Return success response for quiet mode
      return c.json({
        success: true,
        message: `Batch delete initiated for ${keys.length} objects`,
        deletedAt: new Date().toISOString(),
        quiet: true,
      })
    } catch (error) {
      console.error("Batch delete error:", error)

      if (error instanceof HTTPException) {
        throw error
      }

      if (error instanceof Error) {
        throw new HTTPException(500, {
          message: `Batch delete failed: ${error.message}`,
        })
      }

      throw new HTTPException(500, {
        message: "Batch delete failed: Unknown error occurred",
      })
    }
  },
)

export default deleteRoute
