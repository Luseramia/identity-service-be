import { redis } from "./redis";

export async function rateLimiter(context: any): Promise<any> {
  const pathname = new URL(context.request.url).pathname;
  if (
    pathname === "/metrics" ||
    pathname.startsWith("/health/") ||
    pathname.startsWith("/.well-known/")
  ) {
    return;
  }

  const ip = getClientIp(context);
  const key = `rate:global:${ip}`;
  let count: number;
  try {
    count = await redis.incr(key);
    if (count === 1) await redis.expire(key, 60);
  } catch {
    context.set.status = 503;
    return { error: "rate_limit_unavailable" };
  }

  const configured = Number(process.env.RATE_LIMIT_REQUESTS_PER_MINUTE ?? 120);
  const limit = Number.isInteger(configured) && configured > 0 ? configured : 120;
  if (count > limit) {
    context.set.status = 429;
    context.set.headers["retry-after"] = "60";
    return { error: "rate_limit_exceeded" };
  }
}

function getClientIp(context: any) {
  if (context.server?.requestIP) {
    const info = context.server.requestIP(context.request);
    if (info?.address) return info.address;
  }
  if (process.env.TRUST_PROXY_HEADERS !== "true") return "unknown";

  const headers = context.request.headers;
  const cloudflare = headers.get("cf-connecting-ip");
  if (cloudflare) return cloudflare;
  const real = headers.get("x-real-ip");
  if (real) return real;
  const forwarded = headers.get("x-forwarded-for");
  return forwarded?.split(",")[0]?.trim() || "unknown";
}
