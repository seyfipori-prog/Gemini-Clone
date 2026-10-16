const ALLOWED_UPLOAD_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif", "application/pdf"];
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const MAX_REQUEST_CHARS = 20000;
const enc = new TextEncoder();

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // هر چیزی که /api نیست، فایل استاتیک است
    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    try {
      if (url.pathname === "/api/generate" && request.method === "POST")
        return await generate(request, env);

      if (url.pathname === "/api/chats" && request.method === "GET")
        return await listChats(env);

      if (url.pathname === "/api/chats" && request.method === "POST")
        return await saveChat(request, env);

      if (url.pathname === "/api/upload" && request.method === "POST")
        return await upload(request, env);

      return json({ error: "Not found" }, 404);
    } catch (err) {
      return json({ error: err.message }, 500);
    }
  },
};

// ---------- Gemini ----------

async function generate(request, env) {
  const raw = await request.text();
  if (raw.length > MAX_REQUEST_CHARS) return json({ error: "Request too large" }, 413);

  const body = JSON.parse(raw);
  const model = env.MODEL_NAME || "gemini-2.0-flash";
  const base = env.API_BASE_URL || "https://generativelanguage.googleapis.com/v1beta";

  const res = await fetch(`${base}/models/${model}:generateContent`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-goog-api-key": env.GEMINI_API_KEY, // کلید فقط سمت سرور
    },
    body: JSON.stringify({
      contents: body.contents,
      generationConfig: {
        maxOutputTokens: Number(env.MAX_TOKENS) || 2048,
        temperature: Number(env.TEMPERATURE) || 0.7,
      },
    }),
  });

  // پاسخ گوگل را همان‌طور که هست برمی‌گردانیم، تا script.js بدون تغییر کار کند
  return new Response(res.body, {
    status: res.status,
    headers: { "Content-Type": "application/json" },
  });
}

// ---------- D1 ----------

async function listChats(env) {
  const { results } = await env.DB.prepare(
    "SELECT user_message, response_text, created_at FROM chats ORDER BY id ASC LIMIT 200"
  ).all();
  return json({ chats: results });
}

async function saveChat(request, env) {
  const { userMessage, responseText } = await request.json();
  if (typeof userMessage !== "string" || typeof responseText !== "string")
    return json({ error: "Invalid body" }, 400);

  await env.DB.prepare("INSERT INTO chats (user_message, response_text) VALUES (?, ?)")
    .bind(userMessage.slice(0, 10000), responseText.slice(0, 50000))
    .run();

  return json({ ok: true });
}

// ---------- Backblaze B2 (S3 API) ----------

async function upload(request, env) {
  const type = request.headers.get("content-type") || "";
  if (!ALLOWED_UPLOAD_TYPES.includes(type)) return json({ error: "File type not allowed" }, 415);

  const data = await request.arrayBuffer();
  if (data.byteLength > MAX_UPLOAD_BYTES) return json({ error: "File too large" }, 413);

  const key = `uploads/${crypto.randomUUID()}`;
  const res = await s3Put(env, key, data, type);
  if (!res.ok) return json({ error: "Upload failed", status: res.status }, 502);

  return json({ key });
}

async function s3Put(env, key, body, contentType) {
  const region = env.B2_REGION; // مثلاً us-west-004
  const host = `s3.${region}.backblazeb2.com`;
  const path = `/${env.B2_BUCKET}/${key.split("/").map(encodeURIComponent).join("/")}`;

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, ""); // 20260101T000000Z
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256Hex(body);

  // host در امضا هست ولی خود fetch آن را تنظیم می‌کند
  const headers = {
    host,
    "content-type": contentType,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
  };
  const names = Object.keys(headers).sort();
  const signedHeaders = names.join(";");
  const canonicalHeaders = names.map((n) => `${n}:${headers[n]}\n`).join("");

  const canonicalRequest = ["PUT", path, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256Hex(canonicalRequest)].join("\n");

  let k = await hmac(`AWS4${env.B2_APP_KEY}`, dateStamp);
  k = await hmac(k, region);
  k = await hmac(k, "s3");
  k = await hmac(k, "aws4_request");
  const signature = toHex(await hmac(k, stringToSign));

  return fetch(`https://${host}${path}`, {
    method: "PUT",
    headers: {
      "content-type": contentType,
      "x-amz-content-sha256": payloadHash,
      "x-amz-date": amzDate,
      authorization: `AWS4-HMAC-SHA256 Credential=${env.B2_KEY_ID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    },
    body,
  });
}

async function hmac(key, data) {
  const keyBytes = typeof key === "string" ? enc.encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(data)));
}

async function sha256Hex(data) {
  const bytes = typeof data === "string" ? enc.encode(data) : data;
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
