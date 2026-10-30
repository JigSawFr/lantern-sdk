/** HTTP pieces both sides share: origins, the loopback rule of SPEC.md § 2, media types and languages. */

export const PLATFORM_HEADER = "Lantern-Platform";
export const JSON_TYPE = "application/json";
export const PROBLEM_JSON = "application/problem+json";

/** An origin: scheme, host (lower case, IPv6 in brackets) and port, made explicit. */
export interface Origin {
  scheme: "http" | "https";
  host: string;
  port: number;
}

/** The origin of an absolute http(s) URL; a TypeError when it is not one. */
export function origin(url: string): Origin {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new TypeError(`${url.slice(0, 100)} is not an absolute http(s) URL`);
  }
  const scheme = parsed.protocol.slice(0, -1);
  if ((scheme !== "http" && scheme !== "https") || !parsed.hostname) {
    throw new TypeError(`${url.slice(0, 100)} is not an absolute http(s) URL`);
  }
  const port = parsed.port ? Number(parsed.port) : scheme === "https" ? 443 : 80;
  return { scheme, host: parsed.hostname.toLowerCase(), port };
}

export function sameOrigin(a: Origin, b: Origin): boolean {
  return a.scheme === b.scheme && a.host === b.host && a.port === b.port;
}

/** Whether `url` is on `server`'s origin; false for anything that is not an absolute http(s) URL. */
export function onOrigin(url: string, server: Origin): boolean {
  try {
    return sameOrigin(origin(url), server);
  } catch {
    return false;
  }
}

/** 127.0.0.0/8, ::1 or localhost: where plain HTTP is allowed, for testing (SPEC.md § 2). */
export function isLoopback(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) return Number(v4[1]) === 127 && v4.slice(1).every((p) => Number(p) <= 255);
  const mapped = /^::ffff:(127\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(h);
  return mapped?.[1] !== undefined && isLoopback(mapped[1]);
}

/** Whether `url` may be spoken to: HTTPS, or plain HTTP to a loopback address. */
export function plainHttpAllowed(url: string): boolean {
  const o = origin(url);
  return o.scheme === "https" || isLoopback(o.host);
}

/** The media type of a Content-Type, in lower case, without its parameters. */
export function mediaType(contentType: string | null | undefined): string {
  return (contentType ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
}

/** The languages of an Accept-Language header, best first (q=0 left out). */
export function acceptLanguages(header: string | null | undefined): string[] {
  const out: [number, number, string][] = [];
  (header ?? "").split(",").forEach((part, i) => {
    const [tagPart = "", ...params] = part.trim().split(";");
    const tag = tagPart.trim();
    if (!tag || tag === "*") return;
    let q = 1;
    for (const param of params) {
      const [name = "", value = ""] = param.trim().split("=");
      if (name.trim().toLowerCase() === "q") {
        const n = Number(value);
        q = Number.isFinite(n) ? n : 0;
      }
    }
    if (q > 0) out.push([-q, i, tag]);
  });
  out.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  return out.map((x) => x[2]);
}

/** Percent-encodes a path segment or a query value (RFC 3986's unreserved characters left as they are). */
export function quote(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}
