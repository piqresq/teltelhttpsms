type NormalizedInboundSms = {
  from: string;        // sender (msisdn or sender id)
  to: string;          // your DID / destination
  message: string;
  received_at?: string;
};

function badRequest(msg: string) {
  return new Response(msg, { status: 400 });
}

function unauthorized(msg: string) {
  return new Response(msg, { status: 401 });
}

function ok(msg = "OK") {
  return new Response(msg, { status: 200 });
}

function getClientIp(req: Request): string | null {
  // Cloudflare sets this for the true client IP
  return req.headers.get("CF-Connecting-IP");
}

function requireTokenIfConfigured(url: URL, provider: string, env: any): Response | null {
  // Optional: set PROVIDER_<PROVIDER>_TOKEN in Pages env vars.
  // Then require ?token=... (works even if provider cannot set custom headers).
  const key = `PROVIDER_${provider.toUpperCase()}_TOKEN`;
  const expected = env[key];
  if (!expected) return null;

  const got = url.searchParams.get("token") || "";
  if (got !== expected) return unauthorized("Bad token");
  return null;
}

function allowlistIpIfConfigured(req: Request, provider: string, env: any): Response | null {
  // Optional: set PROVIDER_<PROVIDER>_IPS = "1.2.3.4,5.6.7.8"
  const key = `PROVIDER_${provider.toUpperCase()}_IPS`;
  const ipsCsv = env[key];
  if (!ipsCsv) return null;

  const ip = getClientIp(req);
  if (!ip) return unauthorized("Missing client IP");

  const allowed = String(ipsCsv)
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  if (!allowed.includes(ip)) return unauthorized("IP not allowed");
  return null;
}

async function parseDidlogic(req: Request): Promise<NormalizedInboundSms> {
  // DID Logic inbound: POST fields src, dst, message, received_at :contentReference[oaicite:1]{index=1}
  const bodyText = await req.text();
  const form = new URLSearchParams(bodyText);

  const from = form.get("src") || "";
  const to = form.get("dst") || "";
  const message = form.get("message") || "";
  const received_at = form.get("received_at") || undefined;

  if (!from || !to || !message) throw new Error("Missing src/dst/message");
  return { from, to, message, received_at };
}

async function parseGenericJson(req: Request): Promise<NormalizedInboundSms> {
  // Example JSON format:
  // { "from": "...", "to": "...", "message": "...", "received_at": "..." }
  const data = await req.json<any>();
  const from = data?.from || data?.source || "";
  const to = data?.to || data?.destination || "";
  const message = data?.message || data?.text || "";

  if (!from || !to || !message) throw new Error("Missing from/to/message");
  return { from, to, message, received_at: data?.received_at };
}

const PROVIDERS: Record<string, (req: Request) => Promise<NormalizedInboundSms>> = {
  didlogic: parseDidlogic,
  json: parseGenericJson, // a generic option for providers that can send JSON
};

async function forwardToTelTel(sms: NormalizedInboundSms, env: any): Promise<Response> {
  const apiKey = env.TELTEL_API_KEY;
  if (!apiKey) return new Response("Server not configured: TELTEL_API_KEY missing", { status: 500 });

  const apiUrl = env.TELTEL_API_URL || "https://api.teltel.io/v2/sms/action/send/inbox/text";
  const url = new URL(apiUrl);

  url.searchParams.set("from", sms.from);
  url.searchParams.set("to", sms.to);
  url.searchParams.set("message", sms.message);

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 10_000);

  try {
    const resp = await fetch(url.toString(), {
      method: "GET",
      headers: { "X-API-KEY": apiKey },
      signal: controller.signal,
    });

    const text = await resp.text().catch(() => "");
    if (!resp.ok) {
      // Returning non-200 makes many providers retry, which can cause duplicates without a dedupe store.
      return new Response(`TelTel API error: ${resp.status} ${text}`, { status: 502 });
    }

    return ok("OK");
  } finally {
    clearTimeout(t);
  }
}

export async function onRequestPost(context: any): Promise<Response> {
  const provider = String(context.params.provider || "").toLowerCase();
  const handler = PROVIDERS[provider];
  if (!handler) return badRequest(`Unknown provider: ${provider}`);

  const url = new URL(context.request.url);

  // Optional security knobs (set env vars only when you can enforce them)
  const tokenErr = requireTokenIfConfigured(url, provider, context.env); if (tokenErr) return tokenErr;
  const ipErr = allowlistIpIfConfigured(context.request, provider, context.env); if (ipErr) return ipErr;

  let sms: NormalizedInboundSms;
  try {
    sms = await handler(context.request);
  } catch (e: any) {
    return badRequest(`Parse error: ${e?.message || String(e)}`);
  }

  return forwardToTelTel(sms, context.env);
}

// Some providers send GET webhooks. If you need it, keep this:
export async function onRequestGet(context: any): Promise<Response> {
  return new Response("Use POST", { status: 405 });
}
