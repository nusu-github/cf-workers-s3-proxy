const URL_SIGNING_SECRET = process.env.URL_SIGNING_SECRET

if (!URL_SIGNING_SECRET) {
  console.error("Error: URL_SIGNING_SECRET environment variable is not set.")
  console.error("Please set it before running the script, e.g.:")
  console.error(
    "URL_SIGNING_SECRET=your-secret-key node src/generate_signed_url.js <url>",
  )
  process.exit(1)
}

/**
 * Parse command-line arguments
 */
function parseArguments() {
  const args = process.argv.slice(2)
  const options = {
    url: null,
    expires: 86400, // 24 hours default
    json: false,
    quiet: false,
    verbose: false,
    help: false,
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]

    if (arg === "-h" || arg === "--help") {
      options.help = true
    } else if (arg === "-e" || arg === "--expires") {
      if (i + 1 >= args.length) {
        console.error("Error: --expires requires a value")
        process.exit(1)
      }
      const expiresValue = Number.parseInt(args[++i])
      if (Number.isNaN(expiresValue) || expiresValue <= 0) {
        console.error("Error: --expires must be a positive number")
        process.exit(1)
      }
      options.expires = expiresValue
    } else if (arg === "-j" || arg === "--json") {
      options.json = true
    } else if (arg === "-q" || arg === "--quiet") {
      options.quiet = true
    } else if (arg === "-v" || arg === "--verbose") {
      options.verbose = true
    } else if (arg.startsWith("-")) {
      console.error(`Error: Unknown option: ${arg}`)
      showUsage()
      process.exit(1)
    } else {
      if (options.url) {
        console.error("Error: Multiple URLs provided. Only one URL is allowed.")
        process.exit(1)
      }
      options.url = arg
    }
  }

  return options
}

/**
 * Show help information
 */
function showHelp() {
  console.log(`
Cloudflare Workers S3 Proxy - Signed URL Generator
==================================================

Generate signed URLs for S3 proxy with HMAC-SHA256 signatures.

Usage: node src/generate_signed_url.js [options] <url>

Arguments:
  <url>                       The URL to sign

Options:
  -e, --expires <seconds>     Expiration time in seconds from now (default: 86400)
  -h, --help                  Show this help message
  -j, --json                  Output result as JSON
  -q, --quiet                 Quiet mode - only output the signed URL
  -v, --verbose              Verbose output with debug information

Environment Variables:
  URL_SIGNING_SECRET          Secret key for HMAC signing (required)

Examples:
  node src/generate_signed_url.js "http://127.0.0.1:8787/file.txt"
  node src/generate_signed_url.js -e 3600 "http://127.0.0.1:8787/file.txt"
  node src/generate_signed_url.js --json "http://127.0.0.1:8787/file.txt"
  node src/generate_signed_url.js --quiet "http://127.0.0.1:8787/file.txt"
  
  # Using npm script
  npm run generate_signed_url -- "http://127.0.0.1:8787/file.txt"
  npm run generate_signed_url -- --expires 7200 "http://127.0.0.1:8787/file.txt"
	`)
}

/**
 * Show brief usage information
 */
function showUsage() {
  console.error("Usage: node src/generate_signed_url.js [options] <url>")
  console.error("Use --help for detailed information")
}

/**
 * RFC3986 encoding for query parameters following AWS S3 Signature Version 4 standard.
 * This ensures proper encoding where spaces become %20 (not +) and special characters
 * are handled according to AWS specifications.
 *
 * IMPORTANT: This function must exactly match the server-side implementation in index.ts
 */
function rfc3986Encode(str) {
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
 *
 * IMPORTANT: This function must exactly match the server-side implementation in index.ts
 */
function createCanonicalQueryString(searchParams, excludeParam) {
  const params = []

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
 * Generate a signed URL
 */
async function generateSignedUrl(inputUrl, expiresInSeconds, options = {}) {
  // Validate and parse the URL
  let url
  try {
    url = new URL(inputUrl)
  } catch (err) {
    console.error(`Error: Invalid URL: ${inputUrl}`)
    console.error(`Details: ${err.message}`)
    process.exit(1)
  }

  // Set expiration time
  const expirationTimestamp = Math.floor(Date.now() / 1000) + expiresInSeconds
  url.searchParams.set("exp", expirationTimestamp.toString())

  // Create canonical query string excluding signature parameter (not yet added)
  // This must match the server-side verification logic exactly
  const canonicalQueryString = createCanonicalQueryString(
    url.searchParams,
    "sig",
  )

  // Construct data to sign: pathname + canonical query string
  // Only append '?' if there are query parameters (AWS S3 standard)
  const dataToSign = canonicalQueryString
    ? `${url.pathname}?${canonicalQueryString}`
    : url.pathname

  // Debug output to verify what's being signed
  if (options.verbose) {
    console.log("Debug Information:")
    console.log("  Data to sign:", dataToSign)
    console.log("  Canonical query string:", canonicalQueryString)
    console.log("  Expiration timestamp:", expirationTimestamp)
    console.log("  Secret length:", URL_SIGNING_SECRET.length)
    console.log("")
  }

  // Import the secret key for HMAC operation
  const key = await crypto.subtle.importKey(
    "raw", // Format of the key: raw bytes
    new TextEncoder().encode(URL_SIGNING_SECRET), // Key material
    { name: "HMAC", hash: "SHA-256" }, // Algorithm details
    false, // Not extractable
    ["sign"], // Key usages: only signing needed here
  )

  // Generate the signature
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC", // Algorithm
    key, // The imported key
    new TextEncoder().encode(dataToSign), // Data to sign
  )

  // Convert the signature ArrayBuffer to a hexadecimal string
  const signatureHex = Array.from(new Uint8Array(signatureBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")

  // Add the signature as a query parameter
  url.searchParams.set("sig", signatureHex)

  return {
    signedUrl: url.toString(),
    signature: signatureHex,
    expirationTimestamp,
    expiresAt: new Date(expirationTimestamp * 1000).toISOString(),
    inputUrl,
    expiresInSeconds,
  }
}

/**
 * Main application function
 */
async function main() {
  const options = parseArguments()

  if (options.help) {
    showHelp()
    process.exit(0)
  }

  if (!options.url) {
    console.error("Error: URL is required")
    showUsage()
    process.exit(1)
  }

  try {
    const result = await generateSignedUrl(
      options.url,
      options.expires,
      options,
    )

    if (options.quiet) {
      console.log(result.signedUrl)
    } else if (options.json) {
      console.log(JSON.stringify(result, null, 2))
    } else {
      console.log("Signed URL Generator")
      console.log("===================")
      console.log("Signed URL:", result.signedUrl)
      console.log("Signature:", result.signature)
      console.log("Expiration timestamp:", result.expirationTimestamp)
      console.log("Expires at:", result.expiresAt)
      console.log(`Valid for: ${result.expiresInSeconds} seconds`)
    }
  } catch (err) {
    console.error("Error generating signed URL:", err.message)
    if (options.verbose) {
      console.error("Stack trace:", err.stack)
    }
    process.exit(1)
  }
}

// Run the main function
main().catch((err) => {
  console.error("Unexpected error:", err.message)
  process.exit(1)
})
