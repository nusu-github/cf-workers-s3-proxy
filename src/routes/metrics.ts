import { Hono } from "hono"
import { generatePrometheusMetrics } from "../lib/metrics.js"

const metrics = new Hono<{ Bindings: Env }>()

// Prometheus metrics endpoint (text/plain OpenMetrics format)
metrics.get("/__metrics", (_c) => {
  const text = generatePrometheusMetrics()
  return new Response(text, {
    headers: { "Content-Type": "text/plain; version=0.0.4" },
  })
})

export default metrics
