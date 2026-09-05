fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE___NATIVE_TLS");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_VENDOR");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    // OpenSSL and BoringSSL export overlapping symbols. Use native-tls only
    // where it uses a platform TLS library instead of OpenSSL.
    if std::env::var_os("CARGO_FEATURE___NATIVE_TLS").is_some()
        && (std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple")
            || std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows"))
    {
        println!("cargo:rustc-cfg=reqwest_native_tls");
    }
}
