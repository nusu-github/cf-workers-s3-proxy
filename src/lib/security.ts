import { HTTPException } from "hono/http-exception"

import { createCanonicalQueryString, parseInteger } from "./utils.js"

const textEncoder = new TextEncoder()

/**
 * Enhanced URL signature verification following AWS S3 Signature Version 4 standards.
 */
export const verifySignature = async (
  url: URL,
  signingSecret: string,
): Promise<void> => {
  const providedSignature = url.searchParams.get("sig")
  const expirationTimestamp = url.searchParams.get("exp")

  // Missing signature or expiration - return 403 Forbidden
  const hasMissingAuthParams = !providedSignature || !expirationTimestamp
  if (hasMissingAuthParams) {
    throw new HTTPException(403, {
      message: "Missing signature or expiration",
    })
  }

  // Check if URL has expired - return 403 Forbidden
  const expirationTimeMs = Number(expirationTimestamp) * 1000
  const isExpired = Date.now() > expirationTimeMs

  if (isExpired) {
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
  const hasQueryParams = canonicalQueryString.length > 0
  const dataToSign = hasQueryParams
    ? `${url.pathname}?${canonicalQueryString}`
    : url.pathname

  // Import HMAC key for verification
  const hmacSigningKey = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(signingSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"], // Only need verify capability for signature validation
  )

  // Convert received hex signature to bytes for verification
  let receivedSignatureBytes: Uint8Array
  try {
    const hexByteMatches = providedSignature.match(/.{1,2}/g)
    const hasValidHexFormat = hexByteMatches !== null

    if (!hasValidHexFormat) {
      throw new Error("Signature format is invalid - no hex bytes found")
    }

    receivedSignatureBytes = new Uint8Array(
      hexByteMatches.map((hexByte) => Number.parseInt(hexByte, 16)),
    )
  } catch (conversionError: unknown) {
    const errorMessage =
      conversionError instanceof Error
        ? conversionError.message
        : "Invalid signature format"
    throw new HTTPException(403, { message: errorMessage })
  }

  // Verify the signature using Web Crypto API
  const isValidSignature = await crypto.subtle.verify(
    { name: "HMAC", hash: "SHA-256" },
    hmacSigningKey,
    receivedSignatureBytes,
    textEncoder.encode(dataToSign),
  )

  // Invalid signature - return 403 Forbidden (not 401 Unauthorized)
  if (!isValidSignature) {
    throw new HTTPException(403, { message: "Invalid signature" })
  }
}

/**
 * Validates prefix length against configured limits
 */
function validatePrefixLength(prefix: string, maxAllowedLength: number): void {
  const exceedsMaxLength = prefix.length > maxAllowedLength

  if (exceedsMaxLength) {
    throw new HTTPException(400, {
      message: `Prefix too long. Maximum length is ${maxAllowedLength} characters.`,
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

  const lowercasePrefix = prefix.toLowerCase()

  for (const dangerousPattern of traversalPatterns) {
    const containsTraversalPattern = lowercasePrefix.includes(dangerousPattern)

    if (containsTraversalPattern) {
      throw new HTTPException(400, {
        message: "Path traversal detected in prefix parameter.",
      })
    }
  }

  // Additional path traversal checks
  const hasTraversalSequences =
    prefix.startsWith("../") ||
    prefix.endsWith("/..") ||
    prefix.includes("/../") ||
    prefix === ".."

  if (hasTraversalSequences) {
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
  const withoutControlChars = prefix.replace(
    /[\u0000-\u001F\u007F\u0080-\u009F]/g,
    "",
  )

  // Validate allowed characters for S3 object keys
  // S3 allows: letters, numbers, and these special characters: ! - _ . * ' ( ) /
  // Using a more restrictive set for enhanced security, excluding potentially problematic characters
  const allowedCharacterPattern = /^[a-zA-Z0-9\-_.\/']*$/
  const hasOnlyAllowedChars = allowedCharacterPattern.test(withoutControlChars)

  if (!hasOnlyAllowedChars) {
    throw new HTTPException(400, {
      message:
        "Prefix contains invalid characters. Only letters, numbers, and these special characters are allowed: - _ . / '",
    })
  }

  return withoutControlChars
}

/**
 * Normalizes path separators and removes leading slashes
 */
function normalizePath(prefix: string): string {
  // Normalize path separators and remove consecutive slashes
  let normalizedPath = prefix.replace(/\\+/g, "/").replace(/\/+/g, "/")

  // Remove leading slash if present (S3 object keys shouldn't start with /)
  const hasLeadingSlash = normalizedPath.startsWith("/")
  if (hasLeadingSlash) {
    normalizedPath = normalizedPath.substring(1)
  }

  return normalizedPath
}

/**
 * Validates prefix depth and segment length constraints
 */
function validatePrefixStructure(
  prefix: string,
  maxAllowedDepth: number,
): void {
  if (prefix === "") return

  // Limit depth to prevent overly complex prefix structures
  const pathSegments = prefix.split("/")
  const currentDepth = pathSegments.length
  const exceedsMaxDepth = currentDepth > maxAllowedDepth

  if (exceedsMaxDepth) {
    throw new HTTPException(400, {
      message: `Prefix depth exceeds maximum allowed (${maxAllowedDepth} levels).`,
    })
  }

  // Additional security: reject prefixes that are suspiciously long relative to depth
  if (currentDepth > 0) {
    const averageSegmentLength = prefix.length / currentDepth
    const maxReasonableSegmentLength = 128 // Configurable threshold
    const hasExcessivelyLongSegments =
      averageSegmentLength > maxReasonableSegmentLength

    if (hasExcessivelyLongSegments) {
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
  let sanitizedPrefix = prefix.trim()

  // Get configuration limits with defaults
  const maxPrefixLength = parseInteger(
    env.PREFIX_MAX_LENGTH ?? "512",
    "PREFIX_MAX_LENGTH",
  )
  const maxPrefixDepth = parseInteger(
    env.PREFIX_MAX_DEPTH ?? "10",
    "PREFIX_MAX_DEPTH",
  )

  // Validate prefix length
  validatePrefixLength(sanitizedPrefix, maxPrefixLength)

  // Prevent path traversal attempts
  validateNoPathTraversal(sanitizedPrefix)

  // Sanitize characters and validate allowed character set
  sanitizedPrefix = sanitizeAndValidateCharacters(sanitizedPrefix)

  // Normalize path structure
  sanitizedPrefix = normalizePath(sanitizedPrefix)

  // Validate prefix structure constraints
  validatePrefixStructure(sanitizedPrefix, maxPrefixDepth)

  return sanitizedPrefix
}

/**
 * Determines if URL signing should be enforced for the given request.
 * This provides configurable URL signing enforcement for security.
 */
export function shouldEnforceUrlSigning(
  env: Env,
  requestPathname: string,
): boolean {
  // If no signing secret is configured, signing cannot be enforced
  const hasSigningSecret = Boolean(env.URL_SIGNING_SECRET)
  if (!hasSigningSecret) {
    return false
  }

  // Helper to handle boolean/string environment variable
  const parseBooleanEnvVar = (value: boolean | string | undefined): boolean => {
    if (typeof value === "boolean") {
      return value
    }
    if (typeof value === "string") {
      const isTrue = value === "true" || value === "1"
      return isTrue
    }
    return false
  }

  // If global enforcement is enabled
  const isGlobalEnforcementEnabled = parseBooleanEnvVar(env.ENFORCE_URL_SIGNING)
  if (isGlobalEnforcementEnabled) {
    return true
  }

  // Check if specific paths require signing
  const hasSpecificPathRequirements = Boolean(env.URL_SIGNING_REQUIRED_PATHS)
  if (hasSpecificPathRequirements) {
    const requiredPathsString = env.URL_SIGNING_REQUIRED_PATHS
    const requiredPaths = requiredPathsString
      .split(",")
      .map((pathPattern) => pathPattern.trim())
      .filter((pathPattern) => pathPattern.length > 0)

    const matchesRequiredPath = requiredPaths.some((requiredPath) => {
      // Support wildcard matching
      const isWildcardPattern = requiredPath.endsWith("*")

      if (isWildcardPattern) {
        const pathPrefix = requiredPath.slice(0, -1)
        return requestPathname.startsWith(pathPrefix)
      }

      // Exact match or path starts with required path + "/"
      const isExactMatch = requestPathname === requiredPath
      const isSubPath = requestPathname.startsWith(`${requiredPath}/`)

      return isExactMatch || isSubPath
    })

    return matchesRequiredPath
  }

  return false
}
