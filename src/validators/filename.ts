import { HTTPException } from "hono/http-exception"
import { validator } from "hono/validator"

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
    if (filename.match(/%2e|%2f/i)) {
      throw new HTTPException(400, {
        message: "Encoded path characters (%%2e, %%2f) are not allowed.",
      })
    }

    // Security check: Reject direct path traversal attempts
    if (filename.includes("..")) {
      throw new HTTPException(400, { message: "Path traversal detected" })
    }

    // Security check: Windows-style path separators are not allowed
    if (filename.includes("\\")) {
      throw new HTTPException(400, {
        message: "Backslashes are not allowed in paths",
      })
    }

    // Security check: Absolute paths pose security risks
    if (filename.startsWith("/")) {
      throw new HTTPException(400, {
        message: "Absolute paths are not allowed",
      })
    }

    // Path normalization: Remove redundant slashes and empty segments
    // This creates a clean, canonical path representation
    const pathSegments = filename
      .split("/")
      .filter((segment) => segment !== "" && segment !== ".")

    const normalizedPath = pathSegments.join("/")

    // Final validation: Ensure normalized path doesn't contain problematic patterns
    // Double slashes could indicate injection attempts, trailing slashes may cause issues
    if (normalizedPath.includes("//") || normalizedPath.endsWith("/")) {
      throw new HTTPException(400, { message: "Invalid path format" })
    }

    return { filename: normalizedPath }
  },
)
