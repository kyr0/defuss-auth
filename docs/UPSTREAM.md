# Upstream contracts (source inspection)

The upstream GitHub source was inspected on 2026-11-23 via the GitHub connector. No upstream repository was changed and no package download was available in the local execution environment. On 2026-11-24 the pinned packages were installed from the registry and the runtime gates ran; see [VALIDATION.md](../VALIDATION.md).

| Upstream | Inspected contract | Status |
| --- | --- | --- |
| [defuss-jwt](https://github.com/kyr0/defuss/tree/main/packages/jwt) 1.0.2 | Ed25519, JWK thumbprints, jose and Node crypto dependency | Reimplemented independently using Web Crypto |
| [defuss-db](https://github.com/kyr0/defuss-db) 3.2.0, 3.3.0 | openDirectory, openOPFS, ensureCollection, createIndex, snapshot, transaction receipt.result, collection get/find/insert/put/delete | Source verified; native and OPFS runtime gates passed with 3.2.0 (2026-11-24) and 3.3.0 (2026-11-26) |
| [defuss-storage](https://github.com/kyr0/defuss-storage) | open with exclusive create, readExactly, write, size, flush, close, native/OPFS modules | Native and OPFS runtime gates passed 2026-11-24; names must match `[a-z0-9._-]`, at most 128 characters |
| [defuss-vae](https://github.com/kyr0/defuss-vae) | .vae/VERIFY.py, Makefile, gates and documentation | defuss-vae 0.9.0 verifier passed 2026-11-24 |
| [defuss-serve](https://github.com/kyr0/defuss-serve) 0.5.0 | `createServer`, route-declaring plugins, `trustedProxies`, `proxyPlugin`, `remoteAddress` | Registry 0.5.0 hosts `host.plugin()` and the app's `proxyPlugin` in `scripts/host-e2e.mjs` on Node and Bun (2026-11-26) |

The inspected defuss-db manifest pins storage 0.4.1 while the inspected storage repository manifest said 0.4.0. The candidate pins the DB's required storage version, 0.4.1; registry availability and compatibility must be verified during setup. Do not bypass the gate by silently changing versions. The default DB adapter requires Node >=26 or Bun >=1.4.4 according to the inspected manifest. The core/client supports Node 22+ when suitable providers and hashers are supplied.

References: [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517), [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638), [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037), [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725), [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), [Node crypto](https://nodejs.org/api/crypto.html), [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
