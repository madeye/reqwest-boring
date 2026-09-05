These certificates and the private key are test fixtures only. The CA signs the localhost server certificate (serial 2), which is revoked by revoked.crl.pem. Validity spans 2025-2045. The CA private key is intentionally not stored.

`cert-only.p12` contains the public server certificate without a private key,
with password `password`. It verifies that BoringSSL PKCS#12 identity parsing rejects a
certificate-only archive without panicking. Generate it with:

```sh
openssl pkcs12 -export -nokeys -in server.pem -passout pass:password -out cert-only.p12
```
