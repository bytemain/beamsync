#!/usr/bin/env node
import crypto from "node:crypto";

/**
 * Configures Cloudflare R2 bucket lifecycle rules via Cloudflare API:
 * - ephemeral/v1/ objects auto-expire after 24 hours (86400s)
 * - cas/v1/ objects auto-expire after 30 days (2592000s) as a safety ceiling
 * - incomplete multipart uploads abort after 24 hours
 *
 * Usage:
 *   CF_API_TOKEN=... R2_ACCOUNT_ID=... R2_BUCKET_NAME=... node scripts/setup-r2-lifecycle.mjs
 */
async function main() {
  const apiToken = process.env.CF_API_TOKEN?.trim();
  const accountId = process.env.R2_ACCOUNT_ID?.trim();
  const bucketName = process.env.R2_BUCKET_NAME?.trim();

  if (!apiToken || !accountId || !bucketName) {
    console.error(
      "Required env vars: CF_API_TOKEN, R2_ACCOUNT_ID, R2_BUCKET_NAME",
    );
    process.exit(1);
  }

  const payload = {
    rules: [
      {
        id: "beamsync-ephemeral-packs-1d",
        enabled: true,
        conditions: { prefix: "ephemeral/v1/" },
        deleteObjectsTransition: {
          condition: { type: "Age", maxAge: 86_400 },
        },
        abortMultipartUploadsTransition: {
          condition: { type: "Age", maxAge: 86_400 },
        },
      },
      {
        id: "beamsync-cas-packs-30d-ceiling",
        enabled: true,
        conditions: { prefix: "cas/v1/" },
        deleteObjectsTransition: {
          condition: { type: "Age", maxAge: 30 * 86_400 },
        },
        abortMultipartUploadsTransition: {
          condition: { type: "Age", maxAge: 86_400 },
        },
      },
    ],
  };

  const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/r2/buckets/${bucketName}/lifecycle`;
  const res = await fetch(url, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${apiToken}`,
      "content-type": "application/json",
      "x-request-id": crypto.randomUUID(),
    },
    body: JSON.stringify(payload),
  });

  const body = await res.text();
  if (!res.ok) {
    console.error(`Failed to configure R2 lifecycle (${res.status}): ${body}`);
    process.exit(1);
  }
  console.log("R2 lifecycle rules configured:", body);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
