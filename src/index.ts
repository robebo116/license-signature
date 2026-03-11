export default {
  async fetch(request, env, ctx) {
    if (request.method !== "POST") {
      return json({ error: "Only POST allowed" }, 405);
    }

    const { key, hwid } = await request.json();

    if (!key || !hwid) {
      return json({ error: "Missing key or hwid" }, 400);
    }

    /* ================= CACHE CHECK ================= */
    const cache = caches.default;
    const cacheReq = new Request(cacheKey(key, hwid));
    const cached = await cache.match(cacheReq);

    if (cached) {
      return cached; // ✅ còn hạn → khỏi check DB
    }

    /* ================= DB CHECK ================= */
    const record = await env.DB
      .prepare("SELECT * FROM license_keys WHERE key = ?")
      .bind(key)
      .first();

    if (!record) {
      return json({ error: "Invalid key" }, 403);
    }

    if (record.hwid && record.hwid !== hwid) {
      return json({ error: "Key already used on another device" }, 403);
    }

    let activatedAt = record.activated_at;
    let finalHwid = record.hwid;

    if (!record.hwid) {
      const nowIso = nowIsoString();

      await env.DB
        .prepare(
          "UPDATE license_keys SET hwid = ?, activated_at = ? WHERE key = ?"
        )
        .bind(hwid, nowIso, key)
        .run();

      activatedAt = nowIso;
      finalHwid = hwid;
    }

    const activatedTs = Date.parse(activatedAt);
    const expireAtTs =
      activatedTs + record.expire_days * 86400000;

    const nowTs = Date.now();

    if (nowTs > expireAtTs) {
      return json({ error: "Key expired" }, 403);
    }

    const expireAtIso = formatIso(expireAtTs);

    /* ================= PAYLOAD ================= */
    const payload = {
      key,
      hwid: finalHwid,
      activated_at: activatedAt,
      expire_at: expireAtIso,
      expire_at_ts: expireAtTs,
      issued_at: nowTs
    };

    const raw =
      `${payload.key}|${payload.hwid}|` +
      `${payload.expire_at_ts}|${payload.issued_at}`;

    const signature = await sign(raw, env.SECRET);

    const responseBody = json({ ...payload, signature });

    /* ================= CACHE TTL ================= */
    let ttlSeconds = Math.floor((expireAtTs - nowTs) / 1000);

    // Giới hạn TTL Cloudflare (max 1 năm)
    ttlSeconds = Math.min(ttlSeconds, 31536000);

    const cachedResponse = new Response(responseBody.body, {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": `public, max-age=${ttlSeconds}`
      }
    });

    ctx.waitUntil(
      cache.put(cacheReq, cachedResponse.clone())
    );

    return cachedResponse;
  }
};

function json(data: any, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

function cacheKey(key: string, hwid: string) {
  return `https://cache/license/${key}/${hwid}`;
}

function nowIsoString() {
  return new Date().toISOString();
}

function formatIso(ts: number) {
  return new Date(ts).toISOString();
}

async function sign(data: string, secret: string) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(data)
  );

  return [...new Uint8Array(sig)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
