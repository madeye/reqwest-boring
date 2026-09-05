# BoringSSL 4.x does not provide Windows ARM64 assembly. Native builds do not
# get boring-sys's cross-compilation fallback, so select its portable C code.
set(OPENSSL_NO_ASM ON CACHE BOOL "Use portable BoringSSL on Windows ARM64" FORCE)
