import { HTTPException } from "hono/http-exception"
import { validator } from "hono/validator"

export const filenameValidator = validator(
  "param",
  (v?: { filename: string }) => {
    const filename = v?.filename
    if (!filename) throw new HTTPException(400, { message: "Missing filename" })

    // Check for encoded problematic characters after Hono's decoding
    if (filename.match(/%2e|%2f/i)) {
      throw new HTTPException(400, {
        message: "Encoded path characters (%%2e, %%2f) are not allowed.",
      })
    }

    // Reject any path traversal attempts before normalization
    if (filename.includes("..")) {
      throw new HTTPException(400, { message: "Path traversal detected" })
    }

    // Check for backslashes (Windows path separators)
    if (filename.includes("\\")) {
      throw new HTTPException(400, {
        message: "Backslashes are not allowed in paths",
      })
    }

    // Normalize path by removing redundant slashes and empty segments
    const normalizedPath = filename
      .split("/")
      .filter((part) => part !== "" && part !== ".")
      .join("/")

    // Additional security checks
    if (normalizedPath.startsWith("/")) {
      throw new HTTPException(400, {
        message: "Absolute paths are not allowed",
      })
    }

    // Validate the final normalized path doesn't contain problematic patterns
    if (normalizedPath.includes("//") || normalizedPath.endsWith("/")) {
      throw new HTTPException(400, { message: "Invalid path format" })
    }

    return { filename: normalizedPath }
  },
)
