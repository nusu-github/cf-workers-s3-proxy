import { HTTPException } from "hono/http-exception"
import { validator } from "hono/validator"

/**
 * Detects encoded path traversal attempts in filenames
 */
function hasEncodedPathTraversal(filename: string): boolean {
  return filename.match(/%2e|%2f/i) !== null
}

/**
 * Detects direct path traversal attempts
 */
function hasDirectPathTraversal(filename: string): boolean {
  return filename.includes("..")
}

/**
 * Checks for Windows-style path separators
 */
function hasWindowsPathSeparators(filename: string): boolean {
  return filename.includes("\\")
}

/**
 * Checks if path is absolute (starts with forward slash)
 */
function isAbsolutePath(filename: string): boolean {
  return filename.startsWith("/")
}

/**
 * Normalizes path by removing empty segments and current directory references
 */
function normalizePath(filename: string): string {
  const pathSegments = filename
    .split("/")
    .filter((segment) => segment !== "" && segment !== ".")

  return pathSegments.join("/")
}

/**
 * Validates normalized path format
 */
function hasInvalidPathFormat(normalizedPath: string): boolean {
  const hasDoubleSlashes = normalizedPath.includes("//")
  const hasTrailingSlash = normalizedPath.endsWith("/")

  return hasDoubleSlashes || hasTrailingSlash
}

/**
 * Validates and normalizes file path parameters to prevent security vulnerabilities.
 * Implements comprehensive path traversal protection and sanitization.
 */
export const filenameValidator = validator(
  "param",
  (v?: { filename: string }) => {
    const filename = v?.filename

    // Guard clause: Check for missing filename parameter
    if (!filename) {
      throw new HTTPException(400, { message: "Missing filename" })
    }

    // Security check: Detect encoded path traversal attempts
    // These patterns are commonly used in directory traversal attacks
    if (hasEncodedPathTraversal(filename)) {
      throw new HTTPException(400, {
        message: "Encoded path characters (%%2e, %%2f) are not allowed.",
      })
    }

    // Security check: Reject direct path traversal attempts
    if (hasDirectPathTraversal(filename)) {
      throw new HTTPException(400, { message: "Path traversal detected" })
    }

    // Security check: Windows-style path separators are not allowed
    if (hasWindowsPathSeparators(filename)) {
      throw new HTTPException(400, {
        message: "Backslashes are not allowed in paths",
      })
    }

    // Security check: Absolute paths pose security risks
    if (isAbsolutePath(filename)) {
      throw new HTTPException(400, {
        message: "Absolute paths are not allowed",
      })
    }

    // Path normalization: Remove redundant slashes and empty segments
    // This creates a clean, canonical path representation
    const normalizedPath = normalizePath(filename)

    // Final validation: Ensure normalized path doesn't contain problematic patterns
    // Double slashes could indicate injection attempts, trailing slashes may cause issues
    if (hasInvalidPathFormat(normalizedPath)) {
      throw new HTTPException(400, { message: "Invalid path format" })
    }

    return { filename: normalizedPath }
  },
)
