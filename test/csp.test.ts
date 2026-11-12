import test from "node:test";
import assert from "node:assert/strict";
import { allow, grade, lint, makeNonce, parse, serialize, strict } from "../src/index.js";

test("parse keeps first occurrence and ignores junk", () => {
  const d = parse("default-src 'self'; default-src *; ; 9bad x; img-src data: https:");
  assert.deepEqual(d["default-src"], ["'self'"]);
  assert.deepEqual(d["img-src"], ["data:", "https:"]);
  assert.equal(Object.keys(d).length, 2);
});

test("serialize round-trips", () => {
  const h = "default-src 'self'; script-src 'self' https://cdn.example.com; upgrade-insecure-requests";
  assert.equal(serialize(parse(h)), h);
});

test("serialize rejects header and directive smuggling", () => {
  assert.throws(() => serialize({ "script-src": ["'self'; script-src *"] }));
  assert.throws(() => serialize({ "script-src": ["a\r\nSet-Cookie: x=1"] }));
  assert.throws(() => serialize({ "Bad Name": ["x"] }));
});

test("strict baseline grades A and has no findings", () => {
  const f = lint(strict());
  assert.deepEqual(f, []);
  assert.equal(grade(f), "A");
});

test("nonce policy uses strict-dynamic and nonce is random and base64", () => {
  const n = makeNonce();
  assert.match(n, /^[A-Za-z0-9+/]+=*$/);
  assert.notEqual(n, makeNonce());
  const d = strict(n);
  assert.deepEqual(d["script-src"], [`'nonce-${n}'`, "'strict-dynamic'"]);
  assert.equal(lint(d).length, 0);
});

test("allow merges without duplicates and does not mutate", () => {
  const base = strict();
  const next = allow(base, "img-src", "https://img.example.com", "data:");
  assert.deepEqual(next["img-src"], ["'self'", "data:", "https://img.example.com"]);
  assert.deepEqual(base["img-src"], ["'self'", "data:"]);
});

test("lint flags classic weaknesses", () => {
  const f = lint(parse("script-src 'self' 'unsafe-inline' 'unsafe-eval' https: *.cdn.example.com http://old.example.com"));
  const msgs = f.map((x) => x.message).join("|");
  assert.match(msgs, /unsafe-inline/);
  assert.match(msgs, /unsafe-eval/);
  assert.match(msgs, /scheme source 'https:'/);
  assert.match(msgs, /wildcard host/);
  assert.match(msgs, /insecure origin/);
  assert.equal(f[0]?.severity, "high");
  assert.equal(grade(f), "F");
});

test("nonce neutralises unsafe-inline warning", () => {
  const f = lint(parse("script-src 'nonce-abc123' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"));
  assert.equal(f.filter((x) => /unsafe-inline/.test(x.message)).length, 0);
});

test("missing protections and meaningless combinations", () => {
  assert.ok(lint({}).some((x) => x.directive === "script-src" && x.severity === "high"));
  assert.ok(lint(parse("default-src 'none' 'self'")).some((x) => /ignored by browsers/.test(x.message)));
  assert.ok(lint(parse("script-src 'self' 'strict-dynamic'")).some((x) => /no effect/.test(x.message)));
});
