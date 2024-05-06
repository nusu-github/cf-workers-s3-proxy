import { Hono } from "hono";
import { AwsClient } from "aws4fetch";
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

  const req = await aws.sign(
    `https://${c.env.END_POINT}/${c.env.BUCKET_NAME}/${filename}`,
    {
      method: "GET",
      headers: c.res.headers,
    },
  );

  if (req.headers.has("range")) {
    let attempts = c.env.RANGE_RETRY_ATTEMPTS;
    let response;
    do {
      const controller = new AbortController();
      response = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        signal: controller.signal,
      });
      if (response.headers.has("content-range")) {
        if (attempts < c.env.RANGE_RETRY_ATTEMPTS) {
          console.log(
            `Retry for ${req.url} succeeded - response has content-range header`,
          );
        }
        break;
      } else if (response.ok) {
        attempts -= 1;
        console.error(
          `Range header in request for ${req.url} but no content-range header in response. Will retry ${attempts} more times`,
        );
        if (attempts > 0) {
          controller.abort();
        }
      } else {
        break;
      }
    } while (attempts > 0);
    if (attempts <= 0) {
      console.error(
        `Tried range request for ${req.url} ${c.env.RANGE_RETRY_ATTEMPTS} times, but no content-range in response.`,
      );
    }
    return response;
  }

  return fetch(req);
});

export default app;
