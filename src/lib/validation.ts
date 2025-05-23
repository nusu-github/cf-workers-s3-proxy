import { z } from "zod"
import { getBooleanEnv } from "./utils.js"

/**
 * Comprehensive environment variable validation using Zod with fail-fast behavior
 * This ensures all required configurations are present and valid before processing requests
 *
 * Note: Handles both JSON types (from wrangler.jsonc vars) and string types (from secrets, .dev.vars)
 */

// Custom Zod transforms for handling mixed string/boolean types from environment
const booleanFromEnv = z
  .union([z.boolean(), z.string()])
  .transform((val) => {
    if (typeof val === "boolean") return val
    const lower = val.toLowerCase()
    if (lower === "true" || lower === "1") return true
    if (lower === "false" || lower === "0") return false
    throw new Error("must be a boolean value (true/false or 1/0)")
  })
  .optional()

// Custom transform for handling mixed number/string types from environment
const numberFromEnv = z.union([z.number(), z.string()]).transform((val) => {
  if (typeof val === "number") return val
  const num = Number.parseInt(String(val), 10)
  if (Number.isNaN(num)) {
    throw new Error("must be a valid integer")
  }
  return num
})

// URL validation with proper error messages
const httpUrlSchema = z
  .string()
  .url("must be a valid URL")
  .refine(
    (url) => {
      try {
        const parsed = new URL(url)
        return parsed.protocol.startsWith("http")
      } catch {
        return false
      }
    },
    { message: "must be a valid HTTPS URL" },
  )

// AWS region validation
const awsRegionSchema = z
  .string()
  .regex(
    /^[a-z0-9-]+$/,
    "must be a valid AWS region identifier (e.g., us-east-1, eu-west-1)",
  )

// S3 bucket name validation
const s3BucketNameSchema = z
  .string()
  .min(3, "must be at least 3 characters long")
  .max(63, "must be at most 63 characters long")
  .regex(
    /^[a-z0-9.-]+$/,
    "must contain only lowercase letters, numbers, dots, and hyphens",
  )
  .refine((name) => !name.includes(".."), {
    message: "must not contain consecutive dots",
  })
  .refine((name) => !name.startsWith(".") && !name.endsWith("."), {
    message: "must not start or end with dots",
  })

// CORS origins validation
const corsOriginsSchema = z
  .string()
  .optional()
  .refine(
    (origins) => {
      if (!origins || origins === "*") return true
      const originList = origins.split(",").map((o) => o.trim())
      for (const origin of originList) {
        if (origin && origin !== "*") {
          try {
            new URL(origin)
          } catch {
            return false
          }
        }
      }
      return true
    },
    { message: "Invalid CORS origin format. Must be a valid URL or '*'" },
  )

// URL signing paths validation
const urlSigningPathsSchema = z
  .string()
  .optional()
  .refine(
    (paths) => {
      if (!paths) return true
      const pathList = paths.split(",").map((p) => p.trim())
      for (const path of pathList) {
        if (path && !path.startsWith("/")) {
          return false
        }
      }
      return true
    },
    { message: "Paths must start with '/'" },
  )

// URL signing secret validation
const urlSigningSecretSchema = z
  .string()
  .optional()
  .refine(
    (secret) => {
      if (!secret) return true
      return secret.length >= 32
    },
    { message: "must be at least 32 characters long for security" },
  )
  .refine(
    (secret) => {
      if (!secret) return true
      // Check for reasonable entropy
      const hasLowercase = /[a-z]/.test(secret)
      const hasUppercase = /[A-Z]/.test(secret)
      const hasNumbers = /[0-9]/.test(secret)
      const hasSpecialChars = /[^a-zA-Z0-9]/.test(secret)

      const entropyScore = [
        hasLowercase,
        hasUppercase,
        hasNumbers,
        hasSpecialChars,
      ].filter(Boolean).length

      return entropyScore >= 2
    },
    {
      message:
        "should contain a mix of characters for better security (uppercase, lowercase, numbers, special characters)",
    },
  )

// Main environment schema
const envSchema = z
  .object({
    // Required string variables
    END_POINT: httpUrlSchema,
    ACCESS_KEY: z.string().min(1, "is required and must be a non-empty string"),
    SECRET_KEY: z.string().min(1, "is required and must be a non-empty string"),
    BUCKET_NAME: s3BucketNameSchema,
    S3_REGION: awsRegionSchema,

    // Required numeric variable
    RANGE_RETRY_ATTEMPTS: numberFromEnv.refine((val) => val >= 1 && val <= 10, {
      message: "must be a valid integer between 1 and 10",
    }),

    // Optional numeric variables with ranges
    CACHE_TTL_SECONDS: numberFromEnv
      .refine((val) => val >= 1 && val <= 604800, {
        message: "must be >= 1 and <= 604800",
      })
      .optional(),

    CACHE_MIN_TTL_SECONDS: numberFromEnv
      .refine((val) => val >= 1 && val <= 86400, {
        message: "must be >= 1 and <= 86400",
      })
      .optional(),

    CACHE_MAX_TTL_SECONDS: numberFromEnv
      .refine((val) => val >= 60 && val <= 604800, {
        message: "must be >= 60 and <= 604800",
      })
      .optional(),

    PREFIX_MAX_LENGTH: numberFromEnv
      .refine((val) => val >= 1 && val <= 1024, {
        message: "must be >= 1 and <= 1024",
      })
      .optional(),

    PREFIX_MAX_DEPTH: numberFromEnv
      .refine((val) => val >= 1 && val <= 50, {
        message: "must be >= 1 and <= 50",
      })
      .optional(),

    // Boolean variables
    CACHE_ENABLED: booleanFromEnv,
    CACHE_OVERRIDE_S3_HEADERS: booleanFromEnv,
    CACHE_DEBUG: booleanFromEnv,
    ENFORCE_URL_SIGNING: booleanFromEnv,
    ENABLE_LIST_ENDPOINT: booleanFromEnv,
    ENABLE_UPLOAD_ENDPOINT: booleanFromEnv,
    ENABLE_DELETE_ENDPOINT: booleanFromEnv,

    // Optional string variables with custom validation
    CORS_ALLOW_ORIGINS: corsOriginsSchema,
    URL_SIGNING_REQUIRED_PATHS: urlSigningPathsSchema,
    URL_SIGNING_SECRET: urlSigningSecretSchema,
    CACHE_PURGE_SECRET: z.string().optional(),
    VERSION: z.string().optional(),
  })
  .refine(
    (data) => {
      // Validate cache TTL relationships
      if (
        data.CACHE_MIN_TTL_SECONDS !== undefined &&
        data.CACHE_MAX_TTL_SECONDS !== undefined
      ) {
        return data.CACHE_MIN_TTL_SECONDS <= data.CACHE_MAX_TTL_SECONDS
      }
      return true
    },
    {
      message: "CACHE_MIN_TTL_SECONDS must be <= CACHE_MAX_TTL_SECONDS",
      path: ["CACHE_MIN_TTL_SECONDS"],
    },
  )
  .refine(
    (data) => {
      // Validate URL signing configuration
      const enforceUrlSigning = getBooleanEnv(data.ENFORCE_URL_SIGNING, false)
      return !(enforceUrlSigning && !data.URL_SIGNING_SECRET)
    },
    {
      message:
        "URL_SIGNING_SECRET is required when ENFORCE_URL_SIGNING is enabled",
      path: ["URL_SIGNING_SECRET"],
    },
  )
  .refine(
    (data) => {
      // Validate URL signing required paths configuration
      if (data.URL_SIGNING_REQUIRED_PATHS) {
        const paths = data.URL_SIGNING_REQUIRED_PATHS.split(",").map((p) =>
          p.trim(),
        )
        if (paths.length > 0 && !data.URL_SIGNING_SECRET) {
          return false
        }
      }
      return true
    },
    {
      message:
        "URL_SIGNING_SECRET is required when URL_SIGNING_REQUIRED_PATHS is configured",
      path: ["URL_SIGNING_SECRET"],
    },
  )

/**
 * Validates environment variables using Zod schema
 * Throws with comprehensive error message if validation fails
 */
export function validateEnvironment(env: Env): void {
  try {
    envSchema.parse(env)
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = error.errors.map((err) => {
        const field = err.path.join(".")
        return `${field} ${err.message}`
      })

      const errorMessage = [
        "❌ Environment variable validation failed:",
        "",
        ...errorMessages.map((error) => `  • ${error}`),
        "",
        "Please check your wrangler.jsonc configuration and environment variables.",
        "Refer to the documentation for proper configuration values.",
      ].join("\n")

      throw new Error(errorMessage)
    }
    throw error
  }
}

// Global flag to ensure validation runs only once per isolate
let environmentValidated = false

/**
 * Ensures environment validation runs exactly once per isolate
 * Implements fail-fast behavior for misconfigured Workers
 */
export function ensureEnvironmentValidated(env: Env): void {
  if (!environmentValidated) {
    validateEnvironment(env)
    environmentValidated = true
    console.log("✅ Environment validation passed successfully")
  }
}
