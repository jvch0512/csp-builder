#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { grade, lint } from "./lint.js";
import { allow, makeNonce, parse, serialize, strict } from "./policy.js";

const USAGE = `csp-builder <command>
  strict [--nonce] [--allow directive=source ...] [--format header|meta|nginx]
  lint <csp string | file | ->        exit 2 on high severity findings`;

function main(argv: string[]): number {
  const [cmd, ...rest] = argv;
  if (cmd === "strict") {
    let d = strict(rest.includes("--nonce") ? makeNonce() : undefined);
    let format = "header";
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === "--allow") {
        const [dir, src] = (rest[++i] ?? "").split("=");
        if (!dir || !src) { console.error("--allow expects directive=source"); return 2; }
        d = allow(d, dir, src);
      } else if (rest[i] === "--format") format = rest[++i] ?? "header";
    }
    const v = serialize(d);
    if (format === "meta") console.log(`<meta http-equiv="Content-Security-Policy" content="${v.replace(/"/g, "&quot;")}">`);
    else if (format === "nginx") console.log(`add_header Content-Security-Policy "${v}" always;`);
    else console.log(`Content-Security-Policy: ${v}`);
    return 0;
  }
  if (cmd === "lint" && rest[0]) {
    let text = rest[0];
    try { text = readFileSync(rest[0] === "-" ? 0 : rest[0], "utf8"); } catch { /* treat argument as the policy itself */ }
    const header = text.replace(/^\s*content-security-policy:\s*/i, "").trim();
    const findings = lint(parse(header));
    for (const f of findings) console.log(`[${f.severity.toUpperCase().padEnd(6)}] ${f.directive}: ${f.message}`);
    console.log(`Grade ${grade(findings)} (${findings.length} finding(s))`);
    return findings.some((f) => f.severity === "high") ? 2 : 0;
  }
  console.error(USAGE);
  return 2;
}

process.exitCode = main(process.argv.slice(2));
