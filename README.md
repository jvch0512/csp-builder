# csp-builder

Build, parse and **lint Content-Security-Policy** headers. TypeScript, strict mode, zero runtime dependencies. Ships a library and a CLI.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## CLI

```bash
npx csp-builder strict --nonce --allow img-src=https://images.example.com
npx csp-builder strict --format nginx
npx csp-builder lint "script-src 'self' 'unsafe-inline' *"
npx csp-builder lint headers.txt            # exits 2 on high-severity findings
```

## Library

```ts
import { strict, allow, serialize, lint, grade, makeNonce } from "csp-builder";

const nonce = makeNonce();
const policy = allow(strict(nonce), "connect-src", "https://api.example.com");
res.setHeader("Content-Security-Policy", serialize(policy));
console.log(grade(lint(policy))); // "A"
```

## What the linter catches

`unsafe-inline` without nonce/hash, `unsafe-eval`, wildcard and scheme sources (`https:`, `data:`), wildcard hosts, plain `http://` origins, missing `object-src`, `base-uri`, `frame-ancestors`, `form-action`, `strict-dynamic` without nonce, and `'none'` mixed with other sources (browsers ignore it).

## Security notes

* `serialize` rejects values containing `;`, `,`, whitespace or CR/LF, which blocks directive injection and header splitting when a policy is assembled from user-influenced data
* Nonces come from the Web Crypto CSPRNG; generate one per response
* Parsing follows the spec rule that the first occurrence of a directive wins
* A CSP is defence in depth, not a substitute for output encoding

## Development

```bash
npm ci && npm test
```

MIT licensed.
