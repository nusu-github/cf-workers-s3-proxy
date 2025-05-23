import crypto from "node:crypto"

// Test configuration
const CONFIG = {
  BASE_URL: process.env.BASE_URL,
  URL_SIGNING_SECRET: process.env.URL_SIGNING_SECRET, // Set this if URL signing is required
  TEST_FILE_SIZE_SMALL: 1024, // 1KB
  TEST_FILE_SIZE_MEDIUM: 1024 * 1024, // 1MB
  TEST_TIMEOUT: 30000, // 30 seconds
}

/**
 * Generate test file content
 */
function generateTestFile(size) {
  const buffer = Buffer.alloc(size)
  crypto.randomFillSync(buffer)
  return buffer
}

/**
 * Calculate MD5 hash of data
 */
function calculateMD5(data) {
  return crypto.createHash("md5").update(data).digest("base64")
}

/**
 * RFC3986 encoding for query parameters
 */
function rfc3986Encode(str) {
  return encodeURIComponent(str).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  )
}

/**
 * Create canonical query string
 */
function createCanonicalQueryString(searchParams, excludeParam) {
  const params = []

  for (const [name, value] of searchParams.entries()) {
    if (!excludeParam || name !== excludeParam) {
      params.push([name, value])
    }
  }

  params.sort(([a], [b]) => a.localeCompare(b))

  const encodedParams = params.map(
    ([name, value]) => `${rfc3986Encode(name)}=${rfc3986Encode(value)}`,
  )

  return encodedParams.join("&")
}

/**
 * Generate signed URL (same logic as generate_signed_url.js)
 */
async function generateSignedUrl(url, expiresInSeconds = 3600) {
  if (!CONFIG.URL_SIGNING_SECRET) {
    return url // Return unsigned URL if no secret
  }

  const urlObj = new URL(url)
  const expirationTimestamp = Math.floor(Date.now() / 1000) + expiresInSeconds
  urlObj.searchParams.set("exp", expirationTimestamp.toString())

  // Create canonical query string excluding signature parameter
  const canonicalQueryString = createCanonicalQueryString(
    urlObj.searchParams,
    "sig",
  )

  // Construct data to sign
  const dataToSign = canonicalQueryString
    ? `${urlObj.pathname}?${canonicalQueryString}`
    : urlObj.pathname

  // Generate signature
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(CONFIG.URL_SIGNING_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )

  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(dataToSign),
  )

  const signatureHex = Array.from(new Uint8Array(signatureBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")

  urlObj.searchParams.set("sig", signatureHex)
  return urlObj.toString()
}

/**
 * Sleep utility
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Test suite for upload functionality
 */
class UploadTestSuite {
  constructor() {
    this.testResults = []
    this.uploadedFiles = [] // Track uploaded files for cleanup
  }

  /**
   * Run a single test
   */
  async runTest(testName, testFn) {
    console.log(`\n🧪 Running test: ${testName}`)
    const startTime = Date.now()

    try {
      await testFn()
      const duration = Date.now() - startTime
      console.log(`✅ ${testName} PASSED (${duration}ms)`)
      this.testResults.push({ name: testName, status: "PASSED", duration })
    } catch (error) {
      const duration = Date.now() - startTime
      console.error(`❌ ${testName} FAILED (${duration}ms)`)
      console.error(`   Error: ${error.message}`)
      if (error.response) {
        console.error(
          `   HTTP Status: ${error.response.status} ${error.response.statusText}`,
        )
        try {
          // Check if the response body has already been consumed
          if (!error.response.bodyUsed) {
            const responseText = await error.response.text()
            console.error(`   Response: ${responseText.substring(0, 500)}`)
          } else {
            console.error("   Response: [Body already consumed]")
          }
        } catch (readError) {
          console.error("   Response: [Could not read response body]")
        }
      }
      this.testResults.push({
        name: testName,
        status: "FAILED",
        duration,
        error: error.message,
      })
    }
  }

  /**
   * Test 1: Direct upload via PUT
   */
  async testDirectUpload() {
    const filename = `test-direct-${Date.now()}.txt`
    const testData = generateTestFile(CONFIG.TEST_FILE_SIZE_SMALL)
    const contentType = "text/plain"

    this.uploadedFiles.push(filename)

    // Generate signed URL if signing is enabled
    const url = await generateSignedUrl(`${CONFIG.BASE_URL}/${filename}`)

    const response = await fetch(url, {
      method: "PUT",
      headers: {
        "Content-Type": contentType,
        "Content-Length": testData.length.toString(),
        "Content-MD5": calculateMD5(testData),
      },
      body: testData,
    })

    if (!response.ok) {
      const errorText = await response.text()
      throw new Error(
        `Direct upload failed: ${response.status} ${response.statusText} - ${errorText}`,
      )
    }

    console.log(`   📁 Uploaded file: ${filename} (${testData.length} bytes)`)

    // Verify the upload by trying to download it
    await sleep(1000) // Wait a bit for eventual consistency
    await this.verifyFileExists(filename, testData)
  }

  /**
   * Test 2: Upload with metadata headers
   */
  async testUploadWithMetadata() {
    const filename = `test-metadata-${Date.now()}.json`
    const testData = Buffer.from(
      JSON.stringify({ test: "data", timestamp: Date.now() }),
    )

    this.uploadedFiles.push(filename)

    const url = await generateSignedUrl(`${CONFIG.BASE_URL}/${filename}`)

    const response = await fetch(url, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": testData.length.toString(),
        "x-amz-meta-test-key": "test-value",
        "x-amz-meta-upload-time": new Date().toISOString(),
        "Cache-Control": "max-age=3600",
      },
      body: testData,
    })

    if (!response.ok) {
      const errorText = await response.text()
      throw new Error(
        `Metadata upload failed: ${response.status} ${response.statusText} - ${errorText}`,
      )
    }

    console.log(`   📁 Uploaded file with metadata: ${filename}`)
    await this.verifyFileExists(filename, testData)
  }

  /**
   * Test 3: Generate and use presigned URL for upload
   */
  async testPresignedUpload() {
    const filename = `test-presigned-${Date.now()}.bin`
    const testData = generateTestFile(CONFIG.TEST_FILE_SIZE_MEDIUM)

    this.uploadedFiles.push(filename)

    // Step 1: Request presigned URL
    const presignedUrl = await generateSignedUrl(
      `${CONFIG.BASE_URL}/presigned-upload`,
    )

    const presignedRequest = {
      key: filename,
      expiresIn: 3600,
      conditions: {
        contentType: "application/octet-stream",
        contentLength: testData.length,
        metadata: {
          "test-id": `test-${Date.now()}`,
        },
      },
    }

    const presignedResponse = await fetch(presignedUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(presignedRequest),
    })

    if (!presignedResponse.ok) {
      const errorText = await presignedResponse.text()
      throw new Error(
        `Presigned URL generation failed: ${presignedResponse.status} ${presignedResponse.statusText} - ${errorText}`,
      )
    }

    const presignedData = await presignedResponse.json()
    console.log(`   🔗 Generated presigned URL for: ${filename}`)

    // Step 2: Upload using the presigned URL
    const uploadHeaders = {
      "Content-Length": testData.length.toString(),
      ...presignedData.requiredHeaders,
    }

    const uploadResponse = await fetch(presignedData.presignedUrl, {
      method: presignedData.method,
      headers: uploadHeaders,
      body: testData,
    })

    if (!uploadResponse.ok) {
      const errorText = await uploadResponse.text()
      throw new Error(
        `Presigned upload failed: ${uploadResponse.status} ${uploadResponse.statusText} - ${errorText}`,
      )
    }

    console.log(
      `   📁 Uploaded via presigned URL: ${filename} (${testData.length} bytes)`,
    )
    await sleep(1000)
    await this.verifyFileExists(filename, testData)
  }

  /**
   * Test 4: Multipart upload initiation
   */
  async testMultipartUploadInitiation() {
    const filename = `test-multipart-${Date.now()}.dat`

    this.uploadedFiles.push(filename) // We'll cleanup even if only partially uploaded

    const url = await generateSignedUrl(
      `${CONFIG.BASE_URL}/${filename}/uploads`,
    )

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "x-amz-meta-multipart-test": "true",
      },
    })

    const responseText = await response.text()

    if (!response.ok) {
      throw new Error(
        `Multipart initiation failed: ${response.status} ${response.statusText} - ${responseText}`,
      )
    }

    console.log(`   🔄 Multipart upload initiated for: ${filename}`)

    // Verify the response contains UploadId (XML response from S3)
    if (!responseText.includes("<UploadId>")) {
      throw new Error("Multipart initiation response missing UploadId")
    }

    console.log("   📋 Response contains UploadId as expected")
  }

  /**
   * Test 5: Upload with range/streaming (large file simulation)
   */
  async testLargeFileUpload() {
    const filename = `test-large-${Date.now()}.bin`
    const testData = generateTestFile(CONFIG.TEST_FILE_SIZE_MEDIUM)

    this.uploadedFiles.push(filename)

    const url = await generateSignedUrl(`${CONFIG.BASE_URL}/${filename}`)

    // Simulate streaming upload
    const response = await fetch(url, {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": testData.length.toString(),
      },
      body: testData,
    })

    if (!response.ok) {
      const errorText = await response.text()
      throw new Error(
        `Large file upload failed: ${response.status} ${response.statusText} - ${errorText}`,
      )
    }

    console.log(
      `   📁 Large file uploaded: ${filename} (${testData.length} bytes)`,
    )
    await sleep(2000) // Longer wait for large files
    await this.verifyFileExists(filename, testData)
  }

  /**
   * Test 6: Error cases
   */
  async testErrorCases() {
    // Test 1: Upload to invalid path
    try {
      const url = await generateSignedUrl(
        `${CONFIG.BASE_URL}/../invalid-path.txt`,
      )
      const response = await fetch(url, {
        method: "PUT",
        body: "test",
      })

      if (response.ok) {
        throw new Error("Expected error for invalid path, but got success")
      }
      console.log(`   ✅ Invalid path correctly rejected (${response.status})`)
    } catch (error) {
      if (error.message.includes("Expected error")) {
        throw error
      }
      console.log("   ✅ Invalid path correctly rejected with error")
    }

    // Test 2: Presigned URL with invalid data
    try {
      const presignedUrl = await generateSignedUrl(
        `${CONFIG.BASE_URL}/presigned-upload`,
      )
      const response = await fetch(presignedUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ invalid: "data" }),
      })

      if (response.ok) {
        throw new Error(
          "Expected error for invalid presigned request, but got success",
        )
      }
      console.log(
        `   ✅ Invalid presigned request correctly rejected (${response.status})`,
      )
    } catch (error) {
      if (error.message.includes("Expected error")) {
        throw error
      }
      console.log("   ✅ Invalid presigned request correctly rejected")
    }
  }

  /**
   * Helper: Verify uploaded file exists and matches expected content
   */
  async verifyFileExists(filename, expectedData) {
    const url = await generateSignedUrl(`${CONFIG.BASE_URL}/${filename}`)

    const response = await fetch(url, { method: "GET" })

    if (!response.ok) {
      throw new Error(
        `Verification failed: Could not download ${filename} (${response.status})`,
      )
    }

    const downloadedData = await response.arrayBuffer()
    const downloadedBuffer = Buffer.from(downloadedData)

    if (!downloadedBuffer.equals(expectedData)) {
      throw new Error(
        `Verification failed: Downloaded data doesn't match uploaded data for ${filename}`,
      )
    }

    console.log(`   ✅ Verified file exists and data matches: ${filename}`)
  }

  /**
   * Cleanup uploaded test files
   */
  async cleanup() {
    console.log("\n🧹 Cleaning up uploaded test files...")

    const cleanupResults = []

    for (const filename of this.uploadedFiles) {
      try {
        const url = await generateSignedUrl(`${CONFIG.BASE_URL}/${filename}`)
        const response = await fetch(url, { method: "DELETE" })

        if (response.ok || response.status === 404) {
          cleanupResults.push({ filename, status: "cleaned" })
          console.log(`   🗑️  Deleted: ${filename}`)
        } else {
          cleanupResults.push({
            filename,
            status: "failed",
            error: response.statusText,
          })
          console.log(
            `   ⚠️  Failed to delete: ${filename} (${response.status})`,
          )
        }
      } catch (error) {
        cleanupResults.push({ filename, status: "error", error: error.message })
        console.log(`   ❌ Error deleting: ${filename} - ${error.message}`)
      }

      await sleep(100) // Brief pause between deletions
    }

    return cleanupResults
  }

  /**
   * Run all tests
   */
  async runAllTests() {
    console.log("🚀 Starting S3 Proxy Upload Tests")
    console.log(`📡 Target URL: ${CONFIG.BASE_URL}`)
    console.log(
      `🔐 URL Signing: ${CONFIG.URL_SIGNING_SECRET ? "Enabled" : "Disabled"}`,
    )
    console.log("============================================================")

    // Run all test cases
    await this.runTest("Direct Upload (PUT)", () => this.testDirectUpload())
    await this.runTest("Upload with Metadata", () =>
      this.testUploadWithMetadata(),
    )
    await this.runTest("Presigned URL Upload", () => this.testPresignedUpload())
    await this.runTest("Multipart Upload Initiation", () =>
      this.testMultipartUploadInitiation(),
    )
    await this.runTest("Large File Upload", () => this.testLargeFileUpload())
    await this.runTest("Error Case Handling", () => this.testErrorCases())

    // Cleanup
    const cleanupResults = await this.cleanup()

    // Print summary
    this.printSummary(cleanupResults)
  }

  /**
   * Print test results summary
   */
  printSummary(cleanupResults) {
    console.log(
      "\n============================================================",
    )
    console.log("📊 TEST SUMMARY")
    console.log("============================================================")

    const passed = this.testResults.filter((r) => r.status === "PASSED").length
    const failed = this.testResults.filter((r) => r.status === "FAILED").length
    const total = this.testResults.length

    console.log(`Total Tests: ${total}`)
    console.log(`Passed: ${passed} ✅`)
    console.log(`Failed: ${failed} ${failed > 0 ? "❌" : ""}`)

    if (failed > 0) {
      console.log("\nFailed Tests:")
      for (const test of this.testResults.filter(
        (r) => r.status === "FAILED",
      )) {
        console.log(`  - ${test.name}: ${test.error}`)
      }
    }

    const totalDuration = this.testResults.reduce(
      (sum, r) => sum + r.duration,
      0,
    )
    console.log(`\nTotal Duration: ${totalDuration}ms`)

    // Cleanup summary
    const cleaned = cleanupResults.filter((r) => r.status === "cleaned").length
    const cleanupFailed = cleanupResults.filter(
      (r) => r.status === "failed" || r.status === "error",
    ).length
    console.log(`\nCleanup: ${cleaned} files deleted, ${cleanupFailed} failed`)

    console.log("\n🎯 Test run completed!")

    // Exit with error code if any tests failed
    if (failed > 0) {
      process.exit(1)
    }
  }
}

/**
 * Main execution
 */
async function main() {
  // Check if required dependencies are available
  if (typeof crypto.subtle === "undefined") {
    console.error(
      "❌ crypto.subtle is not available. Please use Node.js 16+ or enable experimental-global-webcrypto",
    )
    process.exit(1)
  }

  const testSuite = new UploadTestSuite()

  try {
    await testSuite.runAllTests()
  } catch (error) {
    console.error("\n💥 Test suite encountered a fatal error:")
    console.error(error)
    process.exit(1)
  }
}

// Export for use as module
export { UploadTestSuite, generateSignedUrl, CONFIG }

// Run if this file is executed directly
if (
  (process.argv[1] &&
    import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}`) ||
  process.argv[1]?.endsWith("upload-test.js")
) {
  main().catch(console.error)
}
