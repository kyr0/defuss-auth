# v0.2.0 implementation contract

- Replace application memberships with internal tenant claim grants and compact profiles. No membership API, no broad grant exposure in principals.
- Guard every admin mutation with current actor proof and target snapshot in the transaction. Client replay must retain the original identity. Test both reproduced races.
- Add tenant-fixed service identities and key lifecycle, verified email, step-up, password rehash, passwordless email challenge, invitation, explicit registration policy. No federation, TOTP, recovery codes or WebAuthn.
- Compile schemas and infer typed profile data; preserve exact opaque claims. Audit safe metadata atomically, use bounded rate/expiry maintenance, version encryption master keys and signing keys separately.
- Keep modular function-based composition; avoid auth caches that weaken revocation. Persist no access JWT rows on issuance. Retain signing inside session transaction for failure atomicity.
- Verify existing and new tests, types, interoperability, runtime and package gates. Record real evidence and explicitly list pending gates. Persistent format 2 rejects v0.1; no automatic data conversion.

See VALIDATION.md for execution results and open release gates.
