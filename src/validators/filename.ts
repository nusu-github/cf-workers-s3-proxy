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

    // Hono automatically decodes path parameters. Path traversal checks are necessary.
    // Normalize to handle mixed slashes and resolve '.' segments.
    const normalizedPath = filename
      .replace(/\\/g, "/")
      .split("/")
      .reduce((acc, part) => {
        if (part === "..") {
          acc.pop()
        } else if (part !== "." && part !== "") {
          acc.push(part)
        }
        return acc
      }, [] as string[])
      .join("/")

    if (
      normalizedPath.includes("..") ||
      (filename !== normalizedPath && filename.includes(".."))
    ) {
      throw new HTTPException(400, { message: "Path traversal detected" })
    }

    // After normalization, if the path starts with '..' equivalent, it's an attempt to go above root.
    const segments = filename
      .replace(/\\/g, "/")
      .split("/")
      .filter((p) => p && p !== ".")
    if (segments[0] === "..") {
      throw new HTTPException(400, {
        message: "Path traversal - attempt to go above root",
      })
    }

    return { filename: normalizedPath } // Return the normalized path
  },
)
