import { AwsClient } from "aws4fetch"
import { HttpMethod } from "../types/s3.js"

let awsClientInstance: AwsClient | null = null

/**
 * Returns a shared AwsClient instance, initializing it on first use.
 */
export function getAwsClient(env: Env): AwsClient {
  if (!awsClientInstance) {
    awsClientInstance = new AwsClient({
      service: "s3",
      accessKeyId: env.ACCESS_KEY,
      secretAccessKey: env.SECRET_KEY,
      region: env.S3_REGION, // Use explicit S3_REGION instead of parsing from endpoint
    })
  }
  return awsClientInstance
}

/** Helper to construct S3 URLs */
export const getS3BaseUrl = (env: Env) => `${env.END_POINT}/${env.BUCKET_NAME}`

/**
 * Generate presigned URL for S3 operations
 * @param signer - AWS client instance
 * @param url - S3 object URL
 * @param method - HTTP method
 * @param headers - Request headers
 * @param expiresIn - Expiration time in seconds (1-604800)
 * @returns Presigned URL string
 */
export async function generatePresignedUrl(
  signer: AwsClient,
  url: string,
  method: HttpMethod,
  headers = new Headers(),
  expiresIn = 3600,
): Promise<string> {
  // Validate expiration time (S3 limits: 1 second to 7 days)
  if (expiresIn < 1 || expiresIn > 604800) {
    throw new Error(
      "expiresIn must be between 1 second and 7 days (604800 seconds)",
    )
  }

  // Parse the URL to add AWS signature query parameters
  const urlObj = new URL(url)

  // Add standard AWS presigned URL parameters
  urlObj.searchParams.set("X-Amz-Expires", expiresIn.toString())
  urlObj.searchParams.set(
    "X-Amz-SignedHeaders",
    Array.from(headers.keys()).sort().join(";"),
  )

  // Sign the request with aws4fetch
  const signedRequest = await signer.sign(urlObj.toString(), {
    method,
    headers,
  })

  // Return the presigned URL
  return signedRequest.url
}

/** Build signed request and fetch with retry */
export async function s3Fetch(
  signer: AwsClient,
  url: string,
  method: HttpMethod,
  headers: Headers,
  attempts: number,
): Promise<Response> {
  let attempt = 0
  let lastErr: unknown

  while (attempt < attempts) {
    try {
      const signedRequest = await signer.sign(url, {
        method,
        headers: headers,
      })
      const res = await fetch(signedRequest.clone())
      if (method === HttpMethod.GET && headers.has("Range")) {
        if (!res.headers.has("content-range")) {
          throw new Error("Missing content-range")
        }
      }
      if (!res.ok) {
        if (res.status >= 500) {
          throw new Error(`Upstream responded with server error: ${res.status}`)
        }
        const contentLength = Number(res.headers.get("content-length") ?? "0")
        if (contentLength > 0)
          globalThis.__app_metrics.bytesSent += contentLength
        return res
      }
      const contentLength = Number(res.headers.get("content-length") ?? "0")
      if (contentLength > 0) globalThis.__app_metrics.bytesSent += contentLength
      return new Response(res.body, res)
    } catch (e) {
      lastErr = e
      const backoff = 200 * 2 ** attempt + Math.random() * 100
      await new Promise((r) => setTimeout(r, backoff))
      attempt++
    }
  }
  throw new Error(`Failed after ${attempts} attempts: ${String(lastErr)}`)
}
