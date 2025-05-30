import { Hono } from "hono"

/**
 * Health check router for monitoring and service discovery
 * Provides endpoints for application health status and version information
 */
const health = new Hono<{ Bindings: Env }>()

/**
 * Default route handler - returns 404 for root path
 * This prevents accidental exposure of sensitive information on the root endpoint
 */
health.get("/", (c) => {
  return c.notFound()
})

/**
 * Health check endpoint for monitoring systems
 * Returns application status, version, and current timestamp
 * Used by load balancers and monitoring tools to verify service availability
 *
 * @route GET /__health
 * @returns JSON response with status, version, and timestamp
 */
health.get("/__health", (c) =>
  c.json({
    status: "ok",
    version: c.env.VERSION ?? "dev",
    timestamp: new Date().toISOString(),
  }),
)

export default health
