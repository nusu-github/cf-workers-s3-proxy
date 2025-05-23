import { Hono } from "hono"

const health = new Hono<{ Bindings: Env }>()

// Default route - not found
health.get("/", (c) => {
  return c.notFound()
})

// Health check endpoint
health.get("/__health", (c) =>
  c.json({
    status: "ok",
    version: c.env.VERSION ?? "dev",
    time: new Date().toISOString(),
  }),
)

export default health
