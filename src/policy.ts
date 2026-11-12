export type Directives = Record<string, string[]>;

const KEYWORDS = new Set(["'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'unsafe-hashes'", "'wasm-unsafe-eval'", "'report-sample'"]);
const NAME = /^[a-z][a-z0-9-]*$/;

/** Parse a CSP header value into directives. First occurrence of a directive wins (per spec). */
export function parse(header: string): Directives {
  const out: Directives = {};
  for (const raw of header.split(";")) {
    const parts = raw.trim().split(/\s+/).filter(Boolean);
    const name = parts.shift()?.toLowerCase();
    if (!name || !NAME.test(name) || name in out) continue;
    out[name] = parts;
  }
  return out;
}

/** Serialise directives back into a header value. Refuses values that could smuggle extra directives or headers. */
export function serialize(d: Directives): string {
  return Object.entries(d)
    .map(([name, values]) => {
      if (!NAME.test(name)) throw new Error(`invalid directive name: ${name}`);
      for (const v of values) {
        if (/[;,\s\r\n]/.test(v)) throw new Error(`invalid value in ${name}: ${JSON.stringify(v)}`);
      }
      return [name, ...values].join(" ");
    })
    .join("; ");
}

/** A strict, widely deployable baseline: no inline script, no plugins, no framing, HTTPS upgrade. */
export function strict(nonce?: string): Directives {
  const script = nonce ? ["'nonce-" + nonce + "'", "'strict-dynamic'"] : ["'self'"];
  return {
    "default-src": ["'self'"],
    "script-src": script,
    "style-src": ["'self'"],
    "img-src": ["'self'", "data:"],
    "object-src": ["'none'"],
    "base-uri": ["'none'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
    "upgrade-insecure-requests": [],
  };
}

/** Add sources to a directive without duplicates, returning a new object. */
export function allow(d: Directives, directive: string, ...sources: string[]): Directives {
  const merged = [...new Set([...(d[directive] ?? []), ...sources])];
  return { ...d, [directive]: merged };
}

export function isKeyword(v: string): boolean {
  return KEYWORDS.has(v.toLowerCase());
}

/** Cryptographically random nonce for per-response use. */
export function makeNonce(bytes = 16): string {
  return Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(bytes))).toString("base64");
}
