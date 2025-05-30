/** Convenience parser for integers that throws on NaN - supports both number and string types */
export const parseInteger = (
  value: number | string | undefined,
  fieldName: string,
): number => {
  if (value === undefined || value === null) {
    throw new Error(`${fieldName} binding is missing`)
  }

  // If it's already a number, validate and return it
  if (typeof value === "number") {
    if (Number.isNaN(value) || !Number.isInteger(value)) {
      throw new Error(`${fieldName} is not a valid integer`)
    }
    return value
  }

  // If it's a string, parse it
  const parsedNumber = Number.parseInt(value, 10)
  if (Number.isNaN(parsedNumber)) {
    throw new Error(`${fieldName} is not a valid integer`)
  }
  return parsedNumber
}

/**
 * RFC3986 encoding for query parameters following AWS S3 Signature Version 4 standard.
 * This ensures proper encoding where spaces become %20 (not +) and special characters
 * are handled according to AWS specifications.
 */
export function rfc3986Encode(str: string): string {
  return encodeURIComponent(str).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  )
}

/**
 * Create canonical query string following AWS S3 Signature Version 4 rules:
 * - URI-encode parameter names and values using RFC3986 encoding
 * - Sort parameters alphabetically by name (case-sensitive)
 * - Join with '&' separator
 * - Return empty string if no parameters
 */
export function createCanonicalQueryString(
  searchParams: URLSearchParams,
  excludeParam?: string,
): string {
  const params: Array<[string, string]> = []

  // Collect all parameters except the excluded one (typically 'sig')
  for (const [name, value] of searchParams.entries()) {
    if (!excludeParam || name !== excludeParam) {
      params.push([name, value])
    }
  }

  // Sort parameters by name (case-sensitive alphabetical order)
  params.sort(([a], [b]) => a.localeCompare(b))

  // Encode and format each parameter using RFC3986 encoding
  const encodedParams = params.map(
    ([name, value]) => `${rfc3986Encode(name)}=${rfc3986Encode(value)}`,
  )

  return encodedParams.join("&")
}

/**
 * Helper function to handle boolean environment variables.
 * Parses boolean, string ("true", "false", "1", "0") or returns default.
 */
export const getBooleanEnv = (
  value: boolean | string | undefined,
  defaultValue: boolean,
): boolean => {
  if (value === undefined || value === null) {
    return defaultValue
  }
  if (typeof value === "boolean") {
    return value
  }
  const lowerValue = value.toLowerCase()
  if (lowerValue === "false" || lowerValue === "0") {
    return false
  }
  if (lowerValue === "true" || lowerValue === "1") {
    return true
  }
  return defaultValue
}

/**
 * Removes path traversal attempts and directory separators
 */
function removePathTraversalCharacters(filename: string): string {
  return filename.replace(/[\/\\]/g, "").replace(/\.\./g, "")
}

/**
 * Removes problematic characters for Content-Disposition
 */
function removeProblematicCharacters(filename: string): string {
  // Keep only alphanumeric, dot, hyphen, underscore, space, and some safe punctuation
  let sanitized = filename.replace(/[^a-zA-Z0-9._\-\s()[\]]/g, "")

  // Strip control characters (including Unicode control characters)
  // biome-ignore lint/suspicious/noControlCharactersInRegex: Unicode ranges needed for security validation
  sanitized = sanitized.replace(/[\u0000-\u001F\u007F\u0080-\u009F]/g, "")

  return sanitized
}

/**
 * Normalizes whitespace in filename
 */
function normalizeWhitespace(filename: string): string {
  return filename.replace(/\s+/g, " ").trim()
}

/**
 * Removes problematic starting characters
 */
function removeProblematicStartingCharacters(filename: string): string {
  if (
    filename.startsWith(".") ||
    filename.startsWith("-") ||
    filename.startsWith("_")
  ) {
    return filename.substring(1)
  }
  return filename
}

/**
 * Checks if filename is a Windows reserved name
 */
function isWindowsReservedName(filename: string): boolean {
  const reservedNames = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
  ]
  const nameWithoutExt = filename.split(".")[0]?.toUpperCase() ?? ""
  return reservedNames.includes(nameWithoutExt)
}

/**
 * Enhanced sanitization for Content-Disposition filename parameter.
 * Prevents security issues in filename handling across different browsers and file systems.
 */
export function sanitizeDownloadFilename(
  dlName: string,
  defaultName: string,
): string {
  // Remove leading/trailing whitespace
  let sanitized = dlName.trim()

  // Prevent excessively long filenames
  if (sanitized.length > 255) {
    sanitized = sanitized.substring(0, 255)
  }

  // Apply sanitization steps
  sanitized = removePathTraversalCharacters(sanitized)
  sanitized = removeProblematicCharacters(sanitized)
  sanitized = normalizeWhitespace(sanitized)
  sanitized = removeProblematicStartingCharacters(sanitized)

  // Ensure filename has valid content and isn't empty
  if (!sanitized || sanitized.length === 0) {
    return defaultName
  }

  // Prevent reserved filenames on Windows
  if (isWindowsReservedName(sanitized)) {
    return defaultName
  }

  return sanitized
}
