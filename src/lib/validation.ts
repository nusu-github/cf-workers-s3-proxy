import { z } from "zod"
import { getBooleanEnv } from "./utils.js"

/**
 * Environment variable validation using Zod with fail-fast behavior
 * Ensures all required configurations are present and valid before processing requests
 *
 * Note: Handles both JSON types (from wrangler.jsonc vars) and string types (from secrets, .dev.vars)
 */

// Transform for handling mixed string/boolean types from environment
const booleanTransform = z
  .union([z.boolean(), z.string()])
  .transform((value) => {
    if (typeof value === "boolean") return value

    const normalized = value.toLowerCase()
    if (normalized === "true" || normalized === "1") return true
    if (normalized === "false" || normalized === "0") return false

    throw new Error("must be a boolean value (true/false or 1/0)")
  })
  .optional()

// Transform for handling mixed number/string types from environment
const integerTransform = z
  .union([z.number(), z.string()])
  .transform((value) => {
    if (typeof value === "number") return value

    const parsedNumber = Number.parseInt(String(value), 10)
    if (Number.isNaN(parsedNumber)) {
      throw new Error("must be a valid integer")
    }
    return parsedNumber
  })

/**
 * Creates integer schema with range validation
 */
function createRangedInteger(minValue: number, maxValue: number) {
  return integerTransform
    .refine((value) => value >= minValue && value <= maxValue, {
      message: `must be >= ${minValue} and <= ${maxValue}`,
    })
    .optional()
}

function isValidHttpUrl(url: string): boolean {
  try {
    const parsed = new URL(url)
    return parsed.protocol.startsWith("http")
  } catch {
    return false
  }
}

// URL validation with proper error messages
const httpUrlSchema = z
  .string()
  .url("must be a valid URL")
  .refine(isValidHttpUrl, { message: "must be a valid HTTPS URL" })

// AWS region validation - follows standard AWS region naming pattern
const awsRegionSchema = z
  .string()
  .regex(
    /^[a-z0-9-]+$/,
    "must be a valid AWS region identifier (e.g., us-east-1, eu-west-1)",
  )

function isValidS3BucketName(name: string): boolean {
  if (name.includes("..")) return false
  if (name.startsWith(".") || name.endsWith(".")) return false
  return true
}

// S3 bucket name validation according to AWS specifications
const s3BucketNameSchema = z
  .string()
  .min(3, "must be at least 3 characters long")
  .max(63, "must be at most 63 characters long")
  .regex(
    /^[a-z0-9.-]+$/,
    "must contain only lowercase letters, numbers, dots, and hyphens",
  )
  .refine(isValidS3BucketName, {
    message: "must not contain consecutive dots or start/end with dots",
  })

function validateCorsOrigins(origins: string | undefined): boolean {
  if (!origins || origins === "*") return true

  const originList = origins.split(",").map((origin) => origin.trim())
  return originList.every((origin) => {
    if (!origin || origin === "*") return true

    try {
      new URL(origin)
      return true
    } catch {
      return false
    }
  })
}

// CORS origins validation - supports wildcard or comma-separated URLs
const corsOriginsSchema = z.string().optional().refine(validateCorsOrigins, {
  message: "Invalid CORS origin format. Must be a valid URL or '*'",
})

function validateUrlSigningPaths(paths: string | undefined): boolean {
  if (!paths) return true

  const pathList = paths.split(",").map((path) => path.trim())
  return pathList.every((path) => !path || path.startsWith("/"))
}

// URL signing paths validation - ensures all paths start with '/'
const urlSigningPathsSchema = z
  .string()
  .optional()
  .refine(validateUrlSigningPaths, {
    message: "Paths must start with '/'",
  })

function hasMinimumSecretLength(secret: string | undefined): boolean {
  return !secret || secret.length >= 32
}

function hasAdequateEntropy(secret: string | undefined): boolean {
  if (!secret) return true

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
}

// URL signing secret validation with length and entropy requirements
const urlSigningSecretSchema = z
  .string()
  .optional()
  .refine(hasMinimumSecretLength, {
    message: "must be at least 32 characters long for security",
  })
  .refine(hasAdequateEntropy, {
    message:
      "should contain a mix of characters for better security (uppercase, lowercase, numbers, special characters)",
  })

function validateCacheTtlRelationship(data: {
  CACHE_MIN_TTL_SECONDS?: number
  CACHE_MAX_TTL_SECONDS?: number
}): boolean {
  const { CACHE_MIN_TTL_SECONDS: minTtl, CACHE_MAX_TTL_SECONDS: maxTtl } = data

  if (minTtl !== undefined && maxTtl !== undefined) {
    return minTtl <= maxTtl
  }
  return true
}

function validateUrlSigningConfiguration(data: {
  ENFORCE_URL_SIGNING?: boolean
  URL_SIGNING_SECRET?: string
}): boolean {
  const isEnforced = getBooleanEnv(data.ENFORCE_URL_SIGNING, false)
  return !(isEnforced && !data.URL_SIGNING_SECRET)
}

function validateUrlSigningPathsConfiguration(data: {
  URL_SIGNING_REQUIRED_PATHS?: string
  URL_SIGNING_SECRET?: string
}): boolean {
  const {
    URL_SIGNING_REQUIRED_PATHS: requiredPaths,
    URL_SIGNING_SECRET: secret,
  } = data

  if (!requiredPaths) return true

  const pathList = requiredPaths.split(",").map((path) => path.trim())
  const hasValidPaths = pathList.length > 0 && pathList.some((path) => path)

  return !(hasValidPaths && !secret)
}

// Environment validation schema with comprehensive checks
const envSchema = z
  .object({
    // Required string variables
    END_POINT: httpUrlSchema,
    ACCESS_KEY: z.string().min(1, "is required and must be a non-empty string"),
    SECRET_KEY: z.string().min(1, "is required and must be a non-empty string"),
    BUCKET_NAME: s3BucketNameSchema,
    S3_REGION: awsRegionSchema,

    // Required numeric variable
    RANGE_RETRY_ATTEMPTS: integerTransform.refine(
      (value) => value >= 1 && value <= 10,
      {
        message: "must be a valid integer between 1 and 10",
      },
    ),

    // Optional numeric variables with predefined ranges
    CACHE_TTL_SECONDS: createRangedInteger(1, 604800), // 1 second to 7 days
    CACHE_MIN_TTL_SECONDS: createRangedInteger(1, 86400), // 1 second to 1 day
    CACHE_MAX_TTL_SECONDS: createRangedInteger(60, 604800), // 1 minute to 7 days
    PREFIX_MAX_LENGTH: createRangedInteger(1, 1024),
    PREFIX_MAX_DEPTH: createRangedInteger(1, 50),

    // Boolean feature flags
    CACHE_ENABLED: booleanTransform,
    CACHE_OVERRIDE_S3_HEADERS: booleanTransform,
    CACHE_DEBUG: booleanTransform,
    ENFORCE_URL_SIGNING: booleanTransform,
    ENABLE_LIST_ENDPOINT: booleanTransform,
    ENABLE_UPLOAD_ENDPOINT: booleanTransform,
    ENABLE_DELETE_ENDPOINT: booleanTransform,

    // Optional string variables with custom validation
    CORS_ALLOW_ORIGINS: corsOriginsSchema,
    URL_SIGNING_REQUIRED_PATHS: urlSigningPathsSchema,
    URL_SIGNING_SECRET: urlSigningSecretSchema,
    CACHE_PURGE_SECRET: z.string().optional(),
    VERSION: z.string().optional(),
  })
  .refine(validateCacheTtlRelationship, {
    message: "CACHE_MIN_TTL_SECONDS must be <= CACHE_MAX_TTL_SECONDS",
    path: ["CACHE_MIN_TTL_SECONDS"],
  })
  .refine(validateUrlSigningConfiguration, {
    message:
      "URL_SIGNING_SECRET is required when ENFORCE_URL_SIGNING is enabled",
    path: ["URL_SIGNING_SECRET"],
  })
  .refine(validateUrlSigningPathsConfiguration, {
    message:
      "URL_SIGNING_SECRET is required when URL_SIGNING_REQUIRED_PATHS is configured",
    path: ["URL_SIGNING_SECRET"],
  })

function formatValidationErrors(errors: z.ZodIssue[]): string {
  const errorMessages = errors.map((error) => {
    const fieldPath = error.path.join(".")
    return `${fieldPath} ${error.message}`
  })

  return [
    "❌ Environment variable validation failed:",
    "",
    ...errorMessages.map((error) => `  • ${error}`),
    "",
    "Please check your wrangler.jsonc configuration and environment variables.",
    "Refer to the documentation for proper configuration values.",
  ].join("\n")
}

/**
 * Validates environment variables using Zod schema
 * Throws with comprehensive error message if validation fails
 */
export function validateEnvironment(env: Env): void {
  try {
    envSchema.parse(env)
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedError = formatValidationErrors(error.errors)
      throw new Error(formattedError)
    }
    throw error
  }
}

// Isolate-level validation state to prevent duplicate validation
let isEnvironmentValidated = false

/**
 * Ensures environment validation runs exactly once per isolate
 * Implements fail-fast behavior for misconfigured Workers
 */
export function ensureEnvironmentValidated(env: Env): void {
  if (isEnvironmentValidated) return

  validateEnvironment(env)
  isEnvironmentValidated = true
  console.log("✅ Environment validation passed successfully")
}
