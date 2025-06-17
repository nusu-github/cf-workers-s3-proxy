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
 * Checks if expiration time is within S3 limits
 */
function hasValidExpirationTime(expiresInSeconds: number): boolean {
  const minExpirationSeconds = 1
  const maxExpirationSeconds = 604800 // 7 days

  return (
    expiresInSeconds >= minExpirationSeconds &&
    expiresInSeconds <= maxExpirationSeconds
  )
}

/**
 * Generate presigned URL for S3 operations
 * @param signer - AWS client instance
 * @param url - S3 object URL
 * @param method - HTTP method
 * @param headers - Request headers
 * @param expiresInSeconds - Expiration time in seconds (1-604800)
 * @returns Presigned URL string
 */
export async function generatePresignedUrl(
  signer: AwsClient,
  url: string,
  method: HttpMethod,
  headers = new Headers(),
  expiresInSeconds = 3600,
): Promise<string> {
  // Validate expiration time (S3 limits: 1 second to 7 days)
  if (!hasValidExpirationTime(expiresInSeconds)) {
    throw new Error(
      "expiresInSeconds must be between 1 second and 7 days (604800 seconds)",
    )
  }

  // Parse the URL to add AWS signature query parameters
  const urlObj = new URL(url)

  // Add standard AWS presigned URL parameters
  urlObj.searchParams.set("X-Amz-Expires", expiresInSeconds.toString())

  const sortedHeaderKeys = Array.from(headers.keys()).sort()
  const signedHeadersParam = sortedHeaderKeys.join(";")
  urlObj.searchParams.set("X-Amz-SignedHeaders", signedHeadersParam)

  // Sign the request with aws4fetch
  const signedRequest = await signer.sign(urlObj.toString(), {
    method,
    headers,
  })

  // Return the presigned URL
  return signedRequest.url
}

/**
 * Checks if response should have content-range header for range requests
 */
function shouldHaveContentRange(method: HttpMethod, headers: Headers): boolean {
  return method === HttpMethod.GET && headers.has("Range")
}

/**
 * Validates range request response
 */
function validateRangeResponse(
  method: HttpMethod,
  headers: Headers,
  response: Response,
): void {
  if (shouldHaveContentRange(method, headers)) {
    if (!response.headers.has("content-range")) {
      throw new Error("Missing content-range")
    }
  }
}

/**
 * Checks if response indicates server error
 */
function isServerError(response: Response): boolean {
  return response.status >= 500
}

/**
 * Handles server error responses
 */
function handleServerError(response: Response): Response {
  if (!response.ok) {
    if (isServerError(response)) {
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

/** Build signed request and fetch with retry logic and exponential backoff */
export async function s3Fetch(
  signer: AwsClient,
  url: string,
  method: HttpMethod,
  headers: Headers,
  maxAttempts: number,
): Promise<Response> {
  let attemptCount = 0
  let lastError: unknown

  while (attemptCount < maxAttempts) {
    try {
      return await performS3FetchAttempt(signer, url, method, headers)
    } catch (error) {
      lastError = error

      // Calculate exponential backoff with jitter
      const baseDelayMs = 200
      const exponentialFactor = 2 ** attemptCount
      const jitterMs = Math.random() * 100
      const backoffDelayMs = baseDelayMs * exponentialFactor + jitterMs

      await new Promise((resolve) => setTimeout(resolve, backoffDelayMs))
      attemptCount++
    }
  }

  throw new Error(`Failed after ${maxAttempts} attempts: ${String(lastError)}`)
}
