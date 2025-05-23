import { HTTPException } from "hono/http-exception"

import { createCanonicalQueryString, int } from "./utils.js"

const globalEncoder = new TextEncoder()

/**
 * Enhanced URL signature verification following AWS S3 Signature Version 4 standards.
 */
export const verifySignature = async (
  url: URL,
  secret: string,
): Promise<void> => {
  const sig = url.searchParams.get("sig")
  const exp = url.searchParams.get("exp")

  // Missing signature or expiration - return 403 Forbidden
  if (!sig || !exp) {
    throw new HTTPException(403, {
      message: "Missing signature or expiration",
    })
  }

  // Check if URL has expired - return 403 Forbidden
  if (Date.now() > Number(exp) * 1000) {
    throw new HTTPException(403, { message: "URL expired" })
  }

  // Create canonical query string excluding the signature parameter
  // This follows AWS S3 Signature V4 standard for canonical request construction
  const canonicalQueryString = createCanonicalQueryString(
    url.searchParams,
    "sig",
  )

  // Construct data to sign: pathname + canonical query string
  // Only append '?' if there are query parameters (AWS S3 standard)
  const dataToSign = canonicalQueryString
    ? `${url.pathname}?${canonicalQueryString}`
    : url.pathname

  // Import HMAC key for verification
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    globalEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"], // Only need verify capability for signature validation
  )

  // Convert received hex signature to bytes for verification
  let receivedSigBytes: Uint8Array
  try {
    const matchedBytes = sig.match(/.{1,2}/g)
    if (!matchedBytes) {
      throw new Error("Signature format is invalid - no hex bytes found")
    }
    receivedSigBytes = new Uint8Array(
      matchedBytes.map((byte) => Number.parseInt(byte, 16)),
    )
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Invalid signature format"
    throw new HTTPException(403, { message }) // 403 for invalid signature format
  }

  // Verify the signature using Web Crypto API
  const valid = await crypto.subtle.verify(
    { name: "HMAC", hash: "SHA-256" },
    hmacKey,
    receivedSigBytes,
    globalEncoder.encode(dataToSign),
  )

  // Invalid signature - return 403 Forbidden (not 401 Unauthorized)
  if (!valid) {
    throw new HTTPException(403, { message: "Invalid signature" })
  }
}

/**
 * Validates prefix length against configured limits
 */
function validatePrefixLength(prefix: string, maxLength: number): void {
  if (prefix.length > maxLength) {
    throw new HTTPException(400, {
      message: `Prefix too long. Maximum length is ${maxLength} characters.`,
    })
  }
}

/**
 * Detects and prevents path traversal attempts
 */
function validateNoPathTraversal(prefix: string): void {
  const traversalPatterns = [
    "../",
    "..\\",
    "..",
    "%2e%2e",
    "%2E%2E", // URL encoded ..
    "%2e%2e%2f",
    "%2E%2E%2F", // URL encoded ../
    "%2e%2e%5c",
    "%2E%2E%5C", // URL encoded ..\
  ]

  const lowerPrefix = prefix.toLowerCase()
  for (const pattern of traversalPatterns) {
    if (lowerPrefix.includes(pattern)) {
      throw new HTTPException(400, {
        message: "Path traversal detected in prefix parameter.",
      })
    }
  }

  // Additional path traversal checks
  if (
    prefix.startsWith("../") ||
    prefix.endsWith("/..") ||
    prefix.includes("/../") ||
    prefix === ".."
  ) {
    throw new HTTPException(400, {
      message: "Path traversal detected in prefix parameter.",
    })
  }
}

/**
 * Removes control characters and validates allowed characters
 */
function sanitizeAndValidateCharacters(prefix: string): string {
  // Remove control characters (0x00-0x1F, 0x7F) and other problematic characters
  // biome-ignore lint/suspicious/noControlCharactersInRegex: Unicode ranges needed for security validation
  const sanitized = prefix.replace(/[\u0000-\u001F\u007F\u0080-\u009F]/g, "")

  // Validate allowed characters for S3 object keys
  // S3 allows: letters, numbers, and these special characters: ! - _ . * ' ( ) /
  // A more restrictive set of characters is enforced for security.
  const allowedPattern = /^[a-zA-Z0-9\-_.\/'()*!]*$/
  if (!allowedPattern.test(sanitized)) {
    throw new HTTPException(400, {
      message:
        "Prefix contains invalid characters. Only letters, numbers, and these special characters are allowed: - _ . / ' ( ) * !",
    })
  }

  return sanitized
}

/**
 * Normalizes path separators and removes leading slashes
 */
function normalizePath(prefix: string): string {
  // Normalize path separators and remove consecutive slashes
  let normalized = prefix.replace(/\\+/g, "/").replace(/\/+/g, "/")

  // Remove leading slash if present (S3 object keys shouldn't start with /)
  if (normalized.startsWith("/")) {
    normalized = normalized.substring(1)
  }

  return normalized
}

/**
 * Validates prefix depth and segment length constraints
 */
function validatePrefixStructure(prefix: string, maxDepth: number): void {
  if (prefix === "") return

  // Limit depth to prevent overly complex prefix structures
  const depth = prefix.split("/").length
  if (depth > maxDepth) {
    throw new HTTPException(400, {
      message: `Prefix depth exceeds maximum allowed (${maxDepth} levels).`,
    })
  }

  // Additional security: reject prefixes that are suspiciously long relative to depth
  if (depth > 0) {
    const avgSegmentLength = prefix.length / depth
    if (avgSegmentLength > 128) {
      // Configurable threshold
      throw new HTTPException(400, {
        message: "Prefix segments are excessively long.",
      })
    }
  }
}

/**
 * Validates and sanitizes S3 object key prefixes to prevent security issues
 * and ensure compliance with S3 naming guidelines.
 */
export function validateAndSanitizePrefix(prefix: string, env: Env): string {
  // S3 object key constraints and security considerations
  if (!prefix) return ""

  // Remove leading/trailing whitespace
  let sanitized = prefix.trim()

  // Get configuration limits with defaults
  const maxLength = int(env.PREFIX_MAX_LENGTH ?? "512", "PREFIX_MAX_LENGTH")
  const maxDepth = int(env.PREFIX_MAX_DEPTH ?? "10", "PREFIX_MAX_DEPTH")

  // Validate prefix length
  validatePrefixLength(sanitized, maxLength)

  // Prevent path traversal attempts
  validateNoPathTraversal(sanitized)

  // Sanitize characters and validate allowed character set
  sanitized = sanitizeAndValidateCharacters(sanitized)

  // Normalize path structure
  sanitized = normalizePath(sanitized)

  // Validate prefix structure constraints
  validatePrefixStructure(sanitized, maxDepth)

  return sanitized
}

/**
 * Determines if URL signing should be enforced for the given request.
 * This provides configurable URL signing enforcement for security.
 */
export function shouldEnforceUrlSigning(env: Env, pathname: string): boolean {
  // If no signing secret is configured, signing cannot be enforced
  if (!env.URL_SIGNING_SECRET) {
    return false
  }

  // Helper to handle boolean/string environment variable
  const getBooleanValue = (value: boolean | string | undefined): boolean => {
    if (typeof value === "boolean") {
      return value
    }
    if (typeof value === "string") {
      return value === "true" || value === "1"
    }
    return false
  }

  // If global enforcement is enabled
  if (getBooleanValue(env.ENFORCE_URL_SIGNING)) {
    return true
  }

  // Check if specific paths require signing
  if (env.URL_SIGNING_REQUIRED_PATHS) {
    const requiredPaths = env.URL_SIGNING_REQUIRED_PATHS.split(",")
      .map((p) => p.trim())
      .filter((p) => p.length > 0)

    return requiredPaths.some((requiredPath) => {
      // Support wildcard matching
      if (requiredPath.endsWith("*")) {
        const prefix = requiredPath.slice(0, -1)
        return pathname.startsWith(prefix)
      }
      // Exact match or path starts with required path + "/"
      return (
        pathname === requiredPath || pathname.startsWith(`${requiredPath}/`)
      )
    })
  }

  return false
}
