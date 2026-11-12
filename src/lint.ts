import { Directives, isKeyword } from "./policy.js";

export type Severity = "high" | "medium" | "low";
export interface Finding { severity: Severity; directive: string; message: string }

const FETCH = ["script-src", "style-src", "img-src", "connect-src", "font-src", "frame-src", "media-src", "object-src"];

export function lint(d: Directives): Finding[] {
  const out: Finding[] = [];
  const add = (severity: Severity, directive: string, message: string) => out.push({ severity, directive, message });
  const script = d["script-src"] ?? d["default-src"];
  if (!script) add("high", "script-src", "no script-src or default-src: scripts are unrestricted");
  else {
    const hasNonceOrHash = script.some((v) => /^'(nonce|sha(256|384|512))-/.test(v));
    if (script.includes("'unsafe-inline'") && !hasNonceOrHash) add("high", "script-src", "'unsafe-inline' allows inline script injection (XSS)");
    if (script.includes("'unsafe-eval'")) add("medium", "script-src", "'unsafe-eval' allows eval-style code execution");
    if (script.includes("*")) add("high", "script-src", "wildcard source allows scripts from anywhere");
    for (const v of script) {
      if (v === "http:" || v === "https:" || v === "data:") add("high", "script-src", `scheme source '${v}' is too broad`);
      if (/^https?:\/\/\*\./.test(v) || /^\*\./.test(v)) add("medium", "script-src", `wildcard host '${v}' may include attacker-controllable subdomains`);
      if (v.startsWith("http://")) add("medium", "script-src", `insecure origin '${v}'`);
    }
    if (script.includes("'strict-dynamic'") && !hasNonceOrHash) add("medium", "script-src", "'strict-dynamic' has no effect without a nonce or hash");
  }
  if (!("object-src" in d) && !("default-src" in d)) add("medium", "object-src", "object-src missing: plugin content not restricted");
  else if ((d["object-src"] ?? d["default-src"] ?? []).some((v) => v !== "'none'") && "object-src" in d) add("low", "object-src", "prefer object-src 'none'");
  if (!("base-uri" in d)) add("medium", "base-uri", "base-uri missing: <base> injection can redirect relative script URLs");
  if (!("frame-ancestors" in d)) add("medium", "frame-ancestors", "frame-ancestors missing: clickjacking protection relies on X-Frame-Options");
  if (!("form-action" in d)) add("low", "form-action", "form-action missing: forms can post to any origin");
  for (const name of FETCH) {
    const vals = d[name];
    if (vals && name !== "script-src" && vals.includes("*")) add("low", name, "wildcard source");
  }
  for (const [name, vals] of Object.entries(d)) {
    for (const v of vals) if (v.startsWith("'") && !isKeyword(v) && !/^'(nonce|sha(256|384|512))-[A-Za-z0-9+/=_-]+'$/.test(v)) add("low", name, `unknown quoted keyword ${v}`);
    if (vals.length && vals.every((v) => v === "'none'") === false && vals.includes("'none'")) add("medium", name, "'none' combined with other sources is ignored by browsers");
  }
  return out.sort((a, b) => ["high", "medium", "low"].indexOf(a.severity) - ["high", "medium", "low"].indexOf(b.severity));
}

export function grade(findings: Finding[]): "A" | "B" | "C" | "D" | "F" {
  const score = 100 - findings.reduce((s, f) => s + { high: 25, medium: 10, low: 3 }[f.severity], 0);
  return score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
}
