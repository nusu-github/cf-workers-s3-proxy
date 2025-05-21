import { AwsClient } from "aws4fetch";
import { XMLParser } from "fast-xml-parser";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { HTTPException } from "hono/http-exception";
import { logger } from "hono/logger";
import { requestId } from "hono/request-id";
import { secureHeaders } from "hono/secure-headers";
import { validator } from "hono/validator";

import type { ContentfulStatusCode } from "hono/utils/http-status";

/**
 * Environment bindings – all Worker secrets/vars are strings by default.
 */
export type Env = {
	END_POINT: string;
	ACCESS_KEY: string;
	SECRET_KEY: string;
	BUCKET_NAME: string;
	RANGE_RETRY_ATTEMPTS: string;
	URL_SIGNING_SECRET?: string;
	CORS_ALLOW_ORIGINS?: string;
	CACHE_TTL_SECONDS?: string;
	VERSION?: string;
};

/** Convenience parser for ints that throws on NaN */
const int = (value: string | undefined, key: string): number => {
	if (!value) throw new Error(`${key} binding is missing`);
	const n = Number.parseInt(value, 10);
	if (Number.isNaN(n)) throw new Error(`${key} is not a valid integer`);
	return n;
};

const globalEncoder = new TextEncoder();
const xmlParser = new XMLParser();

let awsClientInstance: AwsClient | null = null;

// Metrics structure on globalThis
interface AppMetrics {
	totalRequests: number;
	totalErrors: number;
	bytesSent: number;
}

declare global {
	// eslint-disable-next-line no-var
	var __app_metrics: AppMetrics;
}

// Initialize metrics counters on globalThis if they don't exist
if (typeof globalThis.__app_metrics === "undefined") {
	globalThis.__app_metrics = {
		totalRequests: 0,
		totalErrors: 0,
		bytesSent: 0,
	};
}

/**
 * Returns a shared AwsClient instance, initializing it on first use.
 */
function getAwsClient(env: Env): AwsClient {
	if (!awsClientInstance) {
		awsClientInstance = new AwsClient({
			service: "s3",
			accessKeyId: env.ACCESS_KEY,
			secretAccessKey: env.SECRET_KEY,
			region: env.END_POINT.split(".")[2] ?? "auto", // Attempt to get region from endpoint
		});
	}
	return awsClientInstance;
}

/**
 * Simple URL‑signature verification used when `URL_SIGNING_SECRET` is present.
 */
const verifySignature = async (url: URL, secret: string): Promise<void> => {
	const sig = url.searchParams.get("sig");
	const exp = url.searchParams.get("exp");
	if (!sig || !exp)
		throw new HTTPException(401, { message: "Missing signature" });
	if (Date.now() > Number(exp) * 1000)
		throw new HTTPException(401, { message: "URL expired" });

	// Prepare data for signing: pathname + sorted query parameters (excluding 'sig')
	const paramsToSign = new URLSearchParams(url.searchParams);
	paramsToSign.delete("sig");
	paramsToSign.sort(); // Canonicalize by sorting parameter names
	const dataToSign = `${url.pathname}?${paramsToSign.toString()}`; // Use template literal

	const hmacKey = await crypto.subtle.importKey(
		"raw",
		globalEncoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign", "verify"], // Add "verify" usage for crypto.subtle.verify
	);

	// Convert the received hex signature to a Uint8Array for verification
	let receivedSigBytes: Uint8Array;
	try {
		const matchedBytes = sig.match(/.{1,2}/g);
		if (!matchedBytes) {
			throw new Error("Signature format is invalid - no hex bytes found");
		}
		receivedSigBytes = new Uint8Array(
			matchedBytes.map((byte) => Number.parseInt(byte, 16)),
		); // Use Number.parseInt and check match
	} catch (e: unknown) {
		// Type error explicitly
		const message = e instanceof Error ? e.message : "Invalid signature format";
		throw new HTTPException(401, { message });
	}

	const valid = await crypto.subtle.verify(
		{ name: "HMAC", hash: "SHA-256" },
		hmacKey,
		receivedSigBytes,
		globalEncoder.encode(dataToSign), // Sign the canonicalized path + query params
	);

	if (!valid) throw new HTTPException(401, { message: "Bad signature" });
};

const app = new Hono<{ Bindings: Env }>();

// ───────────────────────────────────────── Middleware  ─────────────────────────────────────────
app.use("*", secureHeaders());
app.use("*", requestId());
app.use(
	"*",
	cors({
		origin: (origin: string | undefined, c) => {
			if (!origin) return undefined;
			const allow = (c.env.CORS_ALLOW_ORIGINS ?? "")
				.toString()
				.split(",")
				.map((s: string) => s.trim());
			if (allow.includes(origin)) {
				return origin;
			}
			return undefined;
		},
		allowMethods: ["GET", "OPTIONS"],
	}),
);
app.use("*", logger());

// custom error handler for JSON body
app.onError((err, c) => {
	globalThis.__app_metrics.totalErrors++;
	const status = err instanceof HTTPException ? err.status : 500;
	return c.json({ error: err.message ?? "Internal Error" }, status);
});

app.notFound((c) => c.json({ error: "Not Found" }, 404));

// ───────────────────────────────────────── Validators  ─────────────────────────────────────────
const filenameValidator = validator("param", (v?: { filename: string }) => {
	const filename = v?.filename;
	if (!filename) throw new HTTPException(400, { message: "Missing filename" });

	// Check for encoded problematic characters after Hono's decoding
	if (filename.match(/%2e|%2f/i)) {
		throw new HTTPException(400, {
			message: "Encoded path characters (%%2e, %%2f) are not allowed.",
		});
	}

	// Hono automatically decodes path parameters. We need to check for path traversal.
	// Normalize to handle mixed slashes and resolve '.' segments.
	// Note: This is a simplified normalization. For full POSIX/Windows compatibility,
	// a more comprehensive library might be needed if complex inputs are expected.
	const normalizedPath = filename
		.replace(/\\/g, "/")
		.split("/")
		.reduce((acc, part) => {
			if (part === "..") {
				acc.pop();
			} else if (part !== "." && part !== "") {
				acc.push(part);
			}
			return acc;
		}, [] as string[])
		.join("/");

	if (
		normalizedPath.includes("..") ||
		(filename !== normalizedPath && filename.includes(".."))
	) {
		// The second condition (filename.includes("..")) is a safeguard in case normalization
		// itself was tricked, though unlikely with this simple reduce approach.
		// It also catches cases where the original input had ".." but normalization removed it
		// (e.g. "/foo/../bar" becomes "/bar", which is fine, but "../foo" would be problematic if not caught)
		// A truly robust solution would check if the normalized path starts with "../" after reduction.
		throw new HTTPException(400, { message: "Path traversal detected" });
	}

	// After normalization, if the path starts with '..' equivalent, it's an attempt to go above root.
	// This can happen if the original path was like '../something'.
	// The reduce logic would result in `normalizedPath` being empty if it was just `..` or `../`.
	// If the original filename, once split by '/', started with '..', it's a traversal attempt.
	const segments = filename
		.replace(/\\/g, "/")
		.split("/")
		.filter((p) => p && p !== ".");
	if (segments[0] === "..") {
		throw new HTTPException(400, {
			message: "Path traversal - attempt to go above root",
		});
	}

	return { filename: normalizedPath }; // Return the normalized path
});

// ───────────────────────────────────────── Utility  ─────────────────────────────────────────
enum HttpMethod {
	GET = "GET",
	HEAD = "HEAD",
}

/** Helper to construct S3 URLs */
const getS3BaseUrl = (env: Env) =>
	`https://${env.END_POINT}/${env.BUCKET_NAME}`;

/** Build signed request and fetch with retry */
async function s3Fetch(
	signer: AwsClient,
	url: string,
	method: HttpMethod,
	headers: Headers,
	attempts: number,
): Promise<Response> {
	let attempt = 0;
	let lastErr: unknown;

	while (attempt < attempts) {
		try {
			const signedRequest = await signer.sign(url, {
				method,
				headers: headers,
			});
			const res = await fetch(signedRequest.clone());
			if (method === HttpMethod.GET && headers.has("Range")) {
				if (!res.headers.has("content-range")) {
					throw new Error("Missing content-range");
				}
			}
			if (!res.ok) {
				if (res.status >= 500) {
					throw new Error(
						`Upstream responded with server error: ${res.status}`,
					);
				}
				const contentLength = Number(res.headers.get("content-length") ?? "0");
				if (contentLength > 0)
					globalThis.__app_metrics.bytesSent += contentLength;
				return res;
			}
			const contentLength = Number(res.headers.get("content-length") ?? "0");
			if (contentLength > 0)
				globalThis.__app_metrics.bytesSent += contentLength;
			return res;
		} catch (e) {
			lastErr = e;
			const backoff = 200 * 2 ** attempt + Math.random() * 100;
			await new Promise((r) => setTimeout(r, backoff));
			attempt++;
		}
	}
	throw new Error(`Failed after ${attempts} attempts: ${String(lastErr)}`);
}

// ───────────────────────────────────────── Routes  ─────────────────────────────────────────
app.get("/", (c) => {
	return c.notFound();
});

// health check
app.get("/__health", (c) =>
	c.json({
		status: "ok",
		version: c.env.VERSION ?? "dev",
		time: new Date().toISOString(),
	}),
);

// Prometheus metrics (text/plain OpenMetrics format)
app.get("/__metrics", (_c) => {
	const metrics = globalThis.__app_metrics;
	const text = [
		"# HELP worker_requests_total Total HTTP requests",
		"# TYPE worker_requests_total counter",
		`worker_requests_total ${metrics.totalRequests}`,
		"# HELP worker_errors_total Total errors",
		"# TYPE worker_errors_total counter",
		`worker_errors_total ${metrics.totalErrors}`,
		"# HELP worker_bytes_sent Bytes sent to clients",
		"# TYPE worker_bytes_sent counter",
		`worker_bytes_sent ${metrics.bytesSent}`,
	].join("\n");
	return new Response(text, {
		headers: { "Content-Type": "text/plain; version=0.0.4" },
	});
});

// list objects – GET /list?prefix=
app.get("/list", async (c) => {
	globalThis.__app_metrics.totalRequests++;
	const prefix = c.req.query("prefix") ?? "";
	const signer = getAwsClient(c.env);
	const listUrl = new URL(
		`${getS3BaseUrl(c.env)}?list-type=2&prefix=${encodeURIComponent(prefix)}`,
	);
	const resp = await signer
		.sign(listUrl.href, { method: HttpMethod.GET })
		.then((req) => fetch(req));

	if (!resp.ok) {
		throw new HTTPException(resp.status as ContentfulStatusCode, {
			message: resp.statusText,
		});
	}

	const xmlData = await resp.text();
	const parsedXml = xmlParser.parse(xmlData);

	let keys: string[] = [];
	const contents = parsedXml?.ListBucketResult?.Contents;

	if (contents) {
		if (Array.isArray(contents)) {
			keys = contents.map((item: { Key: string }) => item.Key).filter(Boolean);
		} else {
			// Handle case where there's only one item (contents is an object)
			keys = [contents.Key].filter(Boolean);
		}
	}

	return c.json({ keys });
});

// Main handler (GET & HEAD)
app.get("/:filename{.*}", filenameValidator, async (c) => {
	globalThis.__app_metrics.totalRequests++;

	if (c.env.URL_SIGNING_SECRET) {
		await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET);
	}

	const validatedData = c.req.valid("param") as { filename: string }; // Get validated data
	const filename = validatedData.filename; // Use the normalized filename

	const method = c.req.raw.method as HttpMethod;
	const signer = getAwsClient(c.env);
	const url = `${getS3BaseUrl(c.env)}/${filename}`;
	const rangeHeader = c.req.header("range");
	const headers = new Headers();
	if (rangeHeader) headers.set("Range", rangeHeader);

	if (method === HttpMethod.GET) {
		if (c.req.query("download") !== undefined) {
			const defaultName = filename.split("/").pop() || "download";
			let dlName = c.req.query("download") || defaultName;
			// Sanitize dlName: remove non-alphanumeric, non-dot, non-hyphen, non-underscore characters
			dlName = dlName.replace(/[^a-zA-Z0-9._-]/g, "");
			// Strip control characters
			// biome-ignore lint/suspicious/noControlCharactersInRegex: <explanation>
			dlName = dlName.replace(/[\u0000-\u001F\u007F]/g, ""); // Use Unicode escapes for control characters
			// Further ensure it's not empty and doesn't start with problematic characters
			if (!dlName || dlName.startsWith(".") || dlName.startsWith("-")) {
				dlName = defaultName;
			}
			headers.set("Content-Disposition", `attachment; filename="${dlName}"`);
		} else if (c.req.query("inline") !== undefined) {
			headers.set("Content-Disposition", "inline");
		}
	}

	return await s3Fetch(
		signer,
		url,
		method,
		headers,
		int(c.env.RANGE_RETRY_ATTEMPTS, "RANGE_RETRY_ATTEMPTS"),
	);
});

export default app;
