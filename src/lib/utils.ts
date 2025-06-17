/** Convenience parser for integers that throws on NaN - supports both number and string types */
export const parseInteger = (
  value: number | string | undefined,
  fieldName: string,
): number => {
  const isMissing = value === undefined || value === null
  if (isMissing) {
    throw new Error(`${fieldName} binding is missing`)
  }

  // If it's already a number, validate and return it
  if (typeof value === "number") {
    const isValidInteger = !Number.isNaN(value) && Number.isInteger(value)
    if (!isValidInteger) {
      throw new Error(`${fieldName} is not a valid integer`)
    }
    return value
  }

  // If it's a string, parse it
  const parsedInteger = Number.parseInt(value, 10)
  const isValidParsedInteger = !Number.isNaN(parsedInteger)
  if (!isValidParsedInteger) {
    throw new Error(`${fieldName} is not a valid integer`)
  }
  return parsedInteger
}

/**
 * RFC3986 encoding for query parameters following AWS S3 Signature Version 4 standard.
 * This ensures proper encoding where spaces become %20 (not +) and special characters
 * are handled according to AWS specifications.
 */
export function rfc3986Encode(inputString: string): string {
  return encodeURIComponent(inputString).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
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
  excludedParamName?: string,
): string {
  const parameterPairs: Array<[string, string]> = []

  // Collect all parameters except the excluded one (typically 'sig')
  for (const [paramName, paramValue] of searchParams.entries()) {
    const shouldIncludeParam =
      !excludedParamName || paramName !== excludedParamName
    if (shouldIncludeParam) {
      parameterPairs.push([paramName, paramValue])
    }
  }

  // Sort parameters by name (case-sensitive alphabetical order)
  parameterPairs.sort(([nameA], [nameB]) => nameA.localeCompare(nameB))

  // Encode and format each parameter using RFC3986 encoding
  const encodedParameters = parameterPairs.map(
    ([name, value]) => `${rfc3986Encode(name)}=${rfc3986Encode(value)}`,
  )

  return encodedParameters.join("&")
}

/**
 * Helper function to handle boolean environment variables.
 * Parses boolean, string ("true", "false", "1", "0") or returns default.
 */
export const getBooleanEnv = (
  value: boolean | string | undefined,
  defaultValue: boolean,
): boolean => {
  const isMissing = value === undefined || value === null
  if (isMissing) {
    return defaultValue
  }

  if (typeof value === "boolean") {
    return value
  }

  const normalizedValue = value.toLowerCase()
  const isFalsyString = normalizedValue === "false" || normalizedValue === "0"
  if (isFalsyString) {
    return false
  }

  const isTruthyString = normalizedValue === "true" || normalizedValue === "1"
  if (isTruthyString) {
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
  // Keep only alphanumeric, dot, hyphen, underscore, space, and consistent safe punctuation
  let sanitizedFilename = filename.replace(/[^a-zA-Z0-9._\-\s]/g, "")

  // Strip control characters (including Unicode control characters)
  // biome-ignore lint/suspicious/noControlCharactersInRegex: Unicode ranges needed for security validation
  sanitizedFilename = sanitizedFilename.replace(
    /[\u0000-\u001F\u007F\u0080-\u009F]/g,
    "",
  )

  return sanitizedFilename
}

/**
 * Normalizes whitespace in filename
 */
function normalizeWhitespace(filename: string): string {
  return filename.replace(/\s+/g, " ").trim()
}

/**
 * Checks if filename starts with problematic characters
 */
function startsWithProblematicChar(filename: string): boolean {
  return (
    filename.startsWith(".") ||
    filename.startsWith("-") ||
    filename.startsWith("_")
  )
}

/**
 * Removes problematic starting characters
 */
function removeProblematicStartingCharacters(filename: string): string {
  return startsWithProblematicChar(filename) ? filename.substring(1) : filename
}

/**
 * Checks if filename is a Windows reserved name
 */
function isWindowsReservedName(filename: string): boolean {
  const windowsReservedNames = [
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
  const nameParts = filename.split(".")
  const filenameWithoutExtension = nameParts.length > 0 ? nameParts[0]?.toUpperCase() ?? "" : ""
  return windowsReservedNames.includes(filenameWithoutExtension)
}

/**
 * Checks if filename is empty after sanitization
 */
function isEmptyFilename(filename: string): boolean {
  return !filename || filename.length === 0
}

/**
 * Checks if filename exceeds maximum length
 */
function exceedsMaxLength(filename: string, maxLength: number): boolean {
  return filename.length > maxLength
}

/**
 * Enhanced sanitization for Content-Disposition filename parameter.
 * Prevents security issues in filename handling across different browsers and file systems.
 */
export function sanitizeDownloadFilename(
  requestedFilename: string,
  fallbackFilename: string,
): string {
  // Remove leading/trailing whitespace
  let sanitizedName = requestedFilename.trim()

  // Prevent excessively long filenames
  const maxFilenameLength = 255
  if (exceedsMaxLength(sanitizedName, maxFilenameLength)) {
    sanitizedName = sanitizedName.substring(0, maxFilenameLength)
  }

  // Apply sanitization steps
  sanitizedName = removePathTraversalCharacters(sanitizedName)
  sanitizedName = removeProblematicCharacters(sanitizedName)
  sanitizedName = normalizeWhitespace(sanitizedName)
  sanitizedName = removeProblematicStartingCharacters(sanitizedName)

  // Ensure filename has valid content and isn't empty
  if (isEmptyFilename(sanitizedName)) {
    return fallbackFilename
  }

  // Prevent reserved filenames on Windows
  if (isWindowsReservedName(sanitizedName)) {
    return fallbackFilename
  }

  return sanitizedName
}
