import { AwsClient } from "aws4fetch";
import { Hono } from "hono";
import { logger } from "hono/logger";

type Bindings = {
	RANGE_RETRY_ATTEMPTS: number;
	END_POINT: string;
	ACCESS_KEY: string;
	SECRET_KEY: string;
	BUCKET_NAME: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use(logger());

app.get("/", (c) => {
	return c.notFound();
});

app.get("/:filename{.*}", async (c) => {
	const filename = c.req.param("filename");

	const aws = new AwsClient({
		accessKeyId: c.env.ACCESS_KEY,
		secretAccessKey: c.env.SECRET_KEY,
		service: "s3",
	});

	const url = `https://${c.env.END_POINT}/${c.env.BUCKET_NAME}/${filename}`;
	const rangeHeader = c.req.header("range");

	const reqInit: RequestInit = {
		method: "GET",
		headers: {},
	};

	if (rangeHeader) {
		reqInit.headers = {
			Range: rangeHeader,
		};
	}

	const signedRequest = await aws.sign(url, reqInit);

	if (rangeHeader) {
		let attempts = c.env.RANGE_RETRY_ATTEMPTS;
		let response: Response | Promise<Response> = c.notFound();

		do {
			const controller = new AbortController();
			try {
				response = await fetch(signedRequest.url, {
					method: signedRequest.method,
					headers: signedRequest.headers,
					signal: controller.signal,
				});

				if (response.headers.has("content-range")) {
					if (attempts < c.env.RANGE_RETRY_ATTEMPTS) {
						console.log(
							`Retry for ${url} succeeded - response has content-range header`,
						);
					}
					return response;
				}

				if (response.ok) {
					attempts -= 1;
					console.error(
						`Range header in request for ${url} but no content-range header in response. Will retry ${attempts} more times`,
					);
					if (attempts > 0) {
						controller.abort();
					}
				} else {
					break;
				}
			} catch (error) {
				console.error(`Error during fetch for ${url}:`, error);
				attempts -= 1;
			}
		} while (attempts > 0);

		console.error(
			`Tried range request for ${url} ${c.env.RANGE_RETRY_ATTEMPTS} times, but no content-range in response.`,
		);
		return response;
	}

	return fetch(signedRequest);
});

export default app;
