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

/**
 * Validates range request response
 */
function validateRangeResponse(
  method: HttpMethod,
  headers: Headers,
  response: Response,
): void {
  if (method === HttpMethod.GET && headers.has("Range")) {
    if (!response.headers.has("content-range")) {
      throw new Error("Missing content-range")
    }
  }
}

/**
 * Handles server error responses
 */
function handleServerError(response: Response): Response {
  if (!response.ok) {
    if (response.status >= 500) {
      throw new Error(
        `Upstream responded with server error: ${response.status}`,
      )
    }
    return response
  }
  return response
}

/**
 * Performs a single S3 fetch attempt
 */
async function performS3FetchAttempt(
  signer: AwsClient,
  url: string,
  method: HttpMethod,
  headers: Headers,
): Promise<Response> {
  const signedRequest = await signer.sign(url, {
    method,
    headers: headers,
  })

  const response = await fetch(signedRequest.clone())

  validateRangeResponse(method, headers, response)

  const handledResponse = handleServerError(response)

  // Clone the response to avoid "Body has already been used" errors
  if (handledResponse.ok) {
    return handledResponse.clone()
  }

  return handledResponse
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
      return await performS3FetchAttempt(signer, url, method, headers)
    } catch (e) {
      lastErr = e
      const backoff = 200 * 2 ** attempt + Math.random() * 100
      await new Promise((r) => setTimeout(r, backoff))
      attempt++
    }
  }

  throw new Error(`Failed after ${attempts} attempts: ${String(lastErr)}`)
}
