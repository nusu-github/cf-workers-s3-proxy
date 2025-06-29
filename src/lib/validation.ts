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

    const normalizedValue = value.toLowerCase()
    const isTruthy = normalizedValue === "true" || normalizedValue === "1"
    const isFalsy = normalizedValue === "false" || normalizedValue === "0"

    if (isTruthy) return true
    if (isFalsy) return false

    throw new Error("must be a boolean value (true/false or 1/0)")
  })
  .optional()

// Transform for handling mixed number/string types from environment
const integerTransform = z
  .union([z.number(), z.string()])
  .transform((value) => {
    if (typeof value === "number") return value

    const parsedInteger = Number.parseInt(String(value), 10)
    const isValidInteger = !Number.isNaN(parsedInteger)

    if (!isValidInteger) {
      throw new Error("must be a valid integer")
    }
    return parsedInteger
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
    const parsedUrl = new URL(url)
    return parsedUrl.protocol.startsWith("http")
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

function isValidS3BucketName(bucketName: string): boolean {
  const hasConsecutiveDots = bucketName.includes("..")
  const startsWithDot = bucketName.startsWith(".")
  const endsWithDot = bucketName.endsWith(".")

  const hasInvalidDotUsage = hasConsecutiveDots || startsWithDot || endsWithDot
  return !hasInvalidDotUsage
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

function validateCorsOrigins(originsList: string | undefined): boolean {
  const isWildcardOrEmpty = !originsList || originsList === "*"
  if (isWildcardOrEmpty) return true

  const individualOrigins = originsList
    .split(",")
    .map((origin) => origin.trim())
  return individualOrigins.every((origin) => {
    const isWildcardOrEmpty = !origin || origin === "*"
    if (isWildcardOrEmpty) return true

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

function validateUrlSigningPaths(pathsList: string | undefined): boolean {
  if (!pathsList) return true

  const individualPaths = pathsList.split(",").map((path) => path.trim())
  return individualPaths.every((path) => {
    const isEmpty = !path
    const startsWithSlash = path.startsWith("/")
    return isEmpty || startsWithSlash
  })
}

// URL signing paths validation - ensures all paths start with '/'
const urlSigningPathsSchema = z
  .string()
  .optional()
  .refine(validateUrlSigningPaths, {
    message: "Paths must start with '/'",
  })

function hasMinimumSecretLength(signingSecret: string | undefined): boolean {
  const minRequiredLength = 32
  return !signingSecret || signingSecret.length >= minRequiredLength
}

function hasAdequateEntropy(signingSecret: string | undefined): boolean {
  if (!signingSecret) return true

  const hasLowercase = /[a-z]/.test(signingSecret)
  const hasUppercase = /[A-Z]/.test(signingSecret)
  const hasNumbers = /[0-9]/.test(signingSecret)
  const hasSpecialChars = /[^a-zA-Z0-9]/.test(signingSecret)

  const characterTypeCount = [
    hasLowercase,
    hasUppercase,
    hasNumbers,
    hasSpecialChars,
  ].filter(Boolean).length

  const minRequiredCharacterTypes = 2
  return characterTypeCount >= minRequiredCharacterTypes
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

  const bothValuesPresent = minTtl !== undefined && maxTtl !== undefined
  if (bothValuesPresent) {
    return minTtl <= maxTtl
  }
  return true
}

function validateUrlSigningConfiguration(data: {
  ENFORCE_URL_SIGNING?: boolean
  URL_SIGNING_SECRET?: string
}): boolean {
  const isSigningEnforced = getBooleanEnv(data.ENFORCE_URL_SIGNING, false)
  const hasSigningSecret = Boolean(data.URL_SIGNING_SECRET)

  // If signing is enforced, a secret must be provided
  const isValidConfiguration = !isSigningEnforced || hasSigningSecret
  return isValidConfiguration
}

function validateUrlSigningPathsConfiguration(data: {
  URL_SIGNING_REQUIRED_PATHS?: string
  URL_SIGNING_SECRET?: string
}): boolean {
  const {
    URL_SIGNING_REQUIRED_PATHS: requiredPathsString,
    URL_SIGNING_SECRET: signingSecret,
  } = data

  if (!requiredPathsString) return true

  const pathsList = requiredPathsString.split(",").map((path) => path.trim())
  const hasValidPaths = pathsList.length > 0 && pathsList.some((path) => path)
  const hasSigningSecret = Boolean(signingSecret)

  // If paths are configured, a secret must be provided
  const isValidConfiguration = !hasValidPaths || hasSigningSecret
  return isValidConfiguration
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

function formatValidationErrors(validationErrors: z.ZodIssue[]): string {
  const formattedErrorMessages = validationErrors.map((error) => {
    const fieldPath = error.path.join(".")
    return `${fieldPath} ${error.message}`
  })

  return [
    "❌ Environment variable validation failed:",
    "",
    ...formattedErrorMessages.map((error) => `  • ${error}`),
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
  } catch (validationError) {
    if (validationError instanceof z.ZodError) {
      const formattedErrorMessage = formatValidationErrors(
        validationError.errors,
      )
      throw new Error(formattedErrorMessage)
    }
    throw validationError
  }
}

/**
 * Ensures environment validation runs for each request
 * Implements fail-fast behavior for misconfigured Workers
 * Note: Removed global state to ensure thread safety in edge environments
 */
export function ensureEnvironmentValidated(env: Env): void {
  validateEnvironment(env)
  console.log("✅ Environment validation passed successfully")
}
