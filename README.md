# SAML vs OIDC Benchmark

A reproducible lab test comparing a signed SAML 2.0 Response with an OpenID Connect (OIDC) ID token for the same user and claims.

Full write-up: [SAML vs OpenID: Which SSO Protocol Should You Use in 2026?](https://example.com/saml-vs-openid)

## What it measures

1. **Token size:** SAML Response (Base64, as POSTed) vs OIDC ID token, with 3, 20, and 100 groups
2. **Validation time:** XML signature verification vs JWT verification (median and p95)
3. **Bad-input handling:** tampered claims, `DOCTYPE` input, `alg: none`, wrong audience
4. **Configuration effort:** metadata size and number of values each side must exchange

## Results (September 25, 2026)

| Groups | SAML Response | OIDC ID token | Ratio |
|---|---|---|---|
| 3 | 6,152 bytes | 875 bytes | 7.0x |
| 20 | 7,308 bytes | 1,125 bytes | 6.5x |
| 100 | 12,748 bytes | 2,298 bytes | 5.5x |

| Validation | Median | p95 |
|---|---|---|
| SAML assertion (signature + digest) | 0.73 ms | 0.86 ms |
| OIDC ID token (signature + iss/aud/exp) | 0.065 ms | 0.091 ms |

Raw output: [`saml-vs-oidc-lab-results.json`](saml-vs-oidc-lab-results.json)

## Environment

- Python 3.12.3
- signxml 5.1.0, PyJWT 2.7.0, cryptography 46.0.6, lxml 6.0.2
- Single Intel Xeon 2.1 GHz core
- RSA-2048 keys, SHA-256 signatures; SAML assertion signed with embedded X.509 certificate

## Run it yourself

```bash
pip install signxml pyjwt cryptography lxml
python3 saml-vs-oidc-lab-test.py
```

Sizes are deterministic. Timing results vary by CPU.

## Scope and limitations

- Protocol-level test using locally generated keys and tokens.
- Does not measure identity provider console setup time or network latency.
- Library behavior reflects the versions listed above.

## License

MIT
