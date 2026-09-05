#![cfg(all(feature = "__rustls", not(target_arch = "wasm32")))]
use boring::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod, SslVerifyMode, SslVersion},
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509,
    },
};
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use std::{net::SocketAddr, sync::Arc, time::Duration};

fn certificate() -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    cert.append_extension(
        ExtendedKeyUsage::new()
            .server_auth()
            .client_auth()
            .build()
            .unwrap(),
    )
    .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .ip("127.0.0.1")
        .build(&cert.x509v3_context(None, None))
        .unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    (cert.build(), key)
}
async fn server(
    cert: &X509,
    key: &PKey<Private>,
    mtls: bool,
    version: Option<SslVersion>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let mut tls = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    tls.set_certificate(cert).unwrap();
    tls.set_private_key(key).unwrap();
    if let Some(version) = version {
        tls.set_min_proto_version(Some(version)).unwrap();
        tls.set_max_proto_version(Some(version)).unwrap();
    }
    if mtls {
        tls.cert_store_mut().add_cert(cert.clone()).unwrap();
        tls.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }
    tls.set_alpn_select_callback(|_, client| {
        boring::ssl::select_next_proto(b"\x02h2\x08http/1.1", client)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let tls = Arc::new(tls.build());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (io, _) = listener.accept().await.unwrap();
            let tls = tls.clone();
            tokio::spawn(async move {
                if let Ok(io) = tokio_boring::accept(&tls, io).await {
                    let service = hyper::service::service_fn(|_| async {
                        Ok::<_, std::convert::Infallible>(http::Response::new(
                            http_body_util::Full::new(Bytes::from_static(b"boring")),
                        ))
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(io), service)
                    .await;
                }
            });
        }
    });
    (addr, task)
}
fn client(cert: &X509) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .tls_backend_rustls()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .tls_certs_only([reqwest::Certificate::from_der(&cert.to_der().unwrap()).unwrap()])
}

#[tokio::test]
async fn trust_hostname_versions_and_metadata() {
    let (cert, key) = certificate();
    let (addr, task) = server(&cert, &key, false, Some(SslVersion::TLS1_2)).await;
    let url = format!("https://{addr}/");
    let response = client(&cert)
        .tls_info(true)
        .http1_only()
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .unwrap();
    let info = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .unwrap();
    assert_eq!(info.version(), Some(reqwest::tls::Version::TLS_1_2));
    assert_eq!(
        info.peer_certificate(),
        Some(cert.to_der().unwrap().as_slice())
    );
    assert_eq!(response.text().await.unwrap(), "boring");
    assert!(reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .is_err());
    assert!(client(&cert)
        .tls_version_min(reqwest::tls::Version::TLS_1_3)
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .is_err());
    let wrong = format!("https://wrong.example:{}/", addr.port());
    assert!(client(&cert)
        .resolve("wrong.example", addr)
        .build()
        .unwrap()
        .get(&wrong)
        .send()
        .await
        .is_err());
    let response = client(&cert)
        .resolve("wrong.example", addr)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap()
        .get(&wrong)
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "boring");
    task.abort();
}
#[tokio::test]
async fn mutual_tls_identity() {
    let (cert, key) = certificate();
    let (addr, task) = server(&cert, &key, true, None).await;
    let url = format!("https://{addr}/");
    assert!(client(&cert)
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .is_err());
    let mut pem = cert.to_pem().unwrap();
    pem.extend(key.private_key_to_pem_pkcs8().unwrap());
    let identity = reqwest::Identity::from_pem(&pem).unwrap();
    let response = client(&cert)
        .identity(identity.clone())
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "boring");
    task.abort();
}
#[cfg(feature = "http2")]
#[tokio::test]
async fn alpn_selects_http2() {
    let (cert, key) = certificate();
    let (addr, task) = server(&cert, &key, false, None).await;
    let response = client(&cert)
        .build()
        .unwrap()
        .get(format!("https://{addr}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.text().await.unwrap(), "boring");
    task.abort();
}

#[tokio::test]
async fn crl_rejects_revoked_certificate() {
    let ca = X509::from_pem(include_bytes!("support/boring/ca.pem")).unwrap();
    let cert = X509::from_pem(include_bytes!("support/boring/server.pem")).unwrap();
    let key = PKey::private_key_from_pem(include_bytes!("support/boring/server.key.pem")).unwrap();
    let (addr, task) = server(&cert, &key, false, None).await;
    let url = format!("https://{addr}/");
    assert!(client(&ca).build().unwrap().get(&url).send().await.is_ok());
    let crl = reqwest::tls::CertificateRevocationList::from_pem(include_bytes!(
        "support/boring/revoked.crl.pem"
    ))
    .unwrap();
    assert!(client(&ca)
        .tls_crls_only([crl])
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .is_err());
    task.abort();
}

#[tokio::test]
async fn https_proxy_nested_tls_preserves_metadata() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (cert, key) = certificate();
    let (addr, task) = server(&cert, &key, false, None).await;
    let mut tls = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    tls.set_certificate(&cert).unwrap();
    tls.set_private_key(&key).unwrap();
    let tls = tls.build();
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let tunnel = tokio::spawn(async move {
        let (io, _) = proxy.accept().await.unwrap();
        let mut io = tokio_boring::accept(&tls, io).await.unwrap();
        assert!(io.ssl().selected_alpn_protocol().is_none());
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(io.read_u8().await.unwrap());
        }
        assert!(header.starts_with(b"CONNECT "));
        let mut target = tokio::net::TcpStream::connect(addr).await.unwrap();
        io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut io, &mut target).await;
    });
    let response = client(&cert)
        .proxy(reqwest::Proxy::all(format!("https://{proxy_addr}")).unwrap())
        .tls_info(true)
        .build()
        .unwrap()
        .get(format!("https://{addr}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .unwrap()
            .peer_certificate(),
        Some(cert.to_der().unwrap().as_slice())
    );
    assert_eq!(response.text().await.unwrap(), "boring");
    tunnel.abort();
    task.abort();
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn socks_tls_preserves_metadata() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (cert, key) = certificate();
    let (addr, task) = server(&cert, &key, false, None).await;
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let tunnel = tokio::spawn(async move {
        let (mut io, _) = proxy.accept().await.unwrap();
        assert_eq!(io.read_u8().await.unwrap(), 5);
        let n = io.read_u8().await.unwrap();
        let mut methods = vec![0; n as usize];
        io.read_exact(&mut methods).await.unwrap();
        io.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 4];
        io.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [5, 1, 0, 1]);
        let mut destination = [0; 6];
        io.read_exact(&mut destination).await.unwrap();
        assert_eq!(&destination[..4], &[127, 0, 0, 1]);
        assert_eq!(
            u16::from_be_bytes([destination[4], destination[5]]),
            addr.port()
        );
        let mut target = tokio::net::TcpStream::connect(addr).await.unwrap();
        io.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut io, &mut target).await;
    });
    let response = client(&cert)
        .proxy(reqwest::Proxy::all(format!("socks5://{proxy_addr}")).unwrap())
        .tls_info(true)
        .build()
        .unwrap()
        .get(format!("https://{addr}/"))
        .send()
        .await
        .unwrap();
    assert!(response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .unwrap()
        .version()
        .is_some());
    assert_eq!(response.text().await.unwrap(), "boring");
    tunnel.abort();
    task.abort();
}

#[cfg(feature = "__native-tls")]
#[tokio::test]
async fn native_backend_identity_formats() {
    let (cert, key) = certificate();
    let (addr, task) = server(&cert, &key, true, None).await;
    let archive = boring::pkcs12::Pkcs12::builder()
        .build("password", "client", &key, &cert)
        .unwrap()
        .to_der()
        .unwrap();
    assert!(reqwest::Identity::from_pkcs12_der(&archive, "wrong password").is_err());
    let identities = [
        reqwest::Identity::from_pkcs12_der(&archive, "password").unwrap(),
        reqwest::Identity::from_pkcs8_pem(
            &cert.to_pem().unwrap(),
            &key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap(),
    ];
    for identity in identities {
        let response = client(&cert)
            .tls_backend_native()
            .identity(identity.clone())
            .build()
            .unwrap()
            .get(format!("https://{addr}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "boring");
    }
    // The deprecated selector remains callable with the same backend semantics.
    assert!(client(&cert).use_native_tls().build().is_ok());
    task.abort();
}
