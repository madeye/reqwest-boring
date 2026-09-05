#![cfg(feature = "http3")]
#![cfg(not(target_arch = "wasm32"))]

mod support;

use http::header::CONTENT_LENGTH;
use std::error::Error;
use support::server;

fn assert_send_sync<T: Send + Sync>(_: &T) {}

#[tokio::test]
async fn http3_request_full() {
    use http_body_util::BodyExt;

    let server = server::Http3::new().build(move |req| async move {
        assert_eq!(req.headers()[CONTENT_LENGTH], "5");
        let reqb = req.collect().await.unwrap().to_bytes();
        assert_eq!(reqb, "hello");
        http::Response::default()
    });

    let url = format!("https://{}/content-length", server.addr());
    let res_fut = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client builder")
        .post(url)
        .version(http::Version::HTTP_3)
        .body("hello")
        .send();

    assert_send_sync(&res_fut);
    let res = res_fut.await.expect("request");

    assert_eq!(res.version(), http::Version::HTTP_3);
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}

async fn find_free_tcp_addr() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    listener.local_addr().unwrap()
}

#[cfg(feature = "http3")]
#[tokio::test]
async fn http3_test_failed_connection() {
    let addr = find_free_tcp_addr().await;
    let port = addr.port();

    let url = format!("https://[::1]:{port}/");
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .http3_max_idle_timeout(std::time::Duration::from_millis(20))
        .build()
        .expect("client builder");

    let err = client
        .get(&url)
        .version(http::Version::HTTP_3)
        .send()
        .await
        .unwrap_err();

    assert!(err.is_timeout(), "expected timeout: {err:?}");

    let err = client
        .get(&url)
        .version(http::Version::HTTP_3)
        .send()
        .await
        .unwrap_err();

    assert!(err.is_timeout(), "expected timeout: {err:?}");

    let server = server::Http3::new()
        .with_addr(addr)
        .build(|_| async { http::Response::default() });

    let res = client
        .post(&url)
        .version(http::Version::HTTP_3)
        .body("hello")
        .send()
        .await
        .expect("request");

    assert_eq!(res.version(), http::Version::HTTP_3);
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    drop(server);
}

#[cfg(feature = "http3")]
#[tokio::test]
async fn http3_test_concurrent_request() {
    let server = server::Http3::new().build(|req| async move {
        let mut res = http::Response::default();
        *res.body_mut() = reqwest::Body::from(format!("hello {}", req.uri().path()));
        res
    });
    let addr = server.addr();

    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .http3_max_idle_timeout(std::time::Duration::from_millis(20))
        .build()
        .expect("client builder");

    let mut tasks = vec![];
    for i in 0..10 {
        let client = client.clone();
        tasks.push(async move {
            let url = format!("https://{}/{}", addr, i);

            client
                .post(&url)
                .version(http::Version::HTTP_3)
                .send()
                .await
                .expect("request")
        });
    }

    let handlers = tasks.into_iter().map(tokio::spawn).collect::<Vec<_>>();

    for (i, handler) in handlers.into_iter().enumerate() {
        let result = handler.await.unwrap();

        assert_eq!(result.version(), http::Version::HTTP_3);
        assert_eq!(result.status(), reqwest::StatusCode::OK);

        let body = result.text().await.unwrap();
        assert_eq!(body, format!("hello /{}", i));
    }

    drop(server);
}

#[cfg(feature = "http3")]
#[tokio::test]
async fn http3_test_h3_stop_sending_before_response_no_error() {
    // Order of payloads:
    // 1. Server: Response headers
    // 2. Server: STOP_SENDING
    // 3. Server: Response body chunk, ensures following happens after STOP_SENDING
    // 4. Client: Request close
    // 5. Server: Response body chunk and close

    let (response_tx, response_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
    let response_rx = std::sync::Arc::new(std::sync::Mutex::new(Some(response_rx)));
    let server_response_rx = response_rx.clone();

    let server = server::Http3::new().build_with_stop_sending_before_response(
        move |_| {
            let server_response_rx = server_response_rx.clone();
            async move {
                let response_rx = server_response_rx.lock().unwrap().take().unwrap();
                let response_stream =
                    futures_util::stream::unfold(response_rx, |mut rx| async move {
                        rx.recv().await.map(|chunk| {
                            (
                                Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(chunk)),
                                rx,
                            )
                        })
                    });
                let response_body =
                    reqwest::Body::wrap(http_body_util::StreamBody::new(response_stream));
                http::Response::new(response_body)
            }
        },
        0x100,
    );

    let (request_tx, request_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
    let request_stream = futures_util::stream::unfold(request_rx, |mut rx| async move {
        rx.recv().await.map(|chunk| {
            (
                Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(chunk)),
                rx,
            )
        })
    });
    let request_body = reqwest::Body::wrap(http_body_util::StreamBody::new(request_stream));

    let url = format!("https://{}/", server.addr());
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client builder");

    let mut res = client
        .post(&url)
        .version(http::Version::HTTP_3)
        .body(request_body)
        .send()
        .await
        .expect("response");

    assert_eq!(res.version(), http::Version::HTTP_3);
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    response_tx
        .send(bytes::Bytes::from_static(b"first"))
        .unwrap();
    let first = res
        .chunk()
        .await
        .ok()
        .flatten()
        .expect("missing first response chunk");
    assert_eq!(first, bytes::Bytes::from_static(b"first"));

    drop(request_tx);

    response_tx
        .send(bytes::Bytes::from_static(b"second"))
        .unwrap();
    drop(response_tx);

    let second = res
        .chunk()
        .await
        .ok()
        .flatten()
        .expect("missing second response chunk");
    assert_eq!(second, bytes::Bytes::from_static(b"second"));
    assert!(res.chunk().await.expect("read response eof").is_none());
}

#[cfg(feature = "http3")]
#[tokio::test]
async fn http3_test_h3_stop_sending_before_response_no_error_request_body() {
    // Order of payloads:
    // 1. Server: Response headers
    // 2. Server: STOP_SENDING
    // 3. Server: Response body chunk, ensures following happens after STOP_SENDING
    // 4. Client: Request body chunk and close
    // 5. Server: Response body chunk and close

    let (response_tx, response_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
    let response_rx = std::sync::Arc::new(std::sync::Mutex::new(Some(response_rx)));
    let server_response_rx = response_rx.clone();

    let server = server::Http3::new().build_with_stop_sending_before_response(
        move |_| {
            let server_response_rx = server_response_rx.clone();
            async move {
                let response_rx = server_response_rx.lock().unwrap().take().unwrap();
                let response_stream =
                    futures_util::stream::unfold(response_rx, |mut rx| async move {
                        rx.recv().await.map(|chunk| {
                            (
                                Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(chunk)),
                                rx,
                            )
                        })
                    });
                let response_body =
                    reqwest::Body::wrap(http_body_util::StreamBody::new(response_stream));
                http::Response::new(response_body)
            }
        },
        0x100,
    );

    let (request_tx, request_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
    let request_stream = futures_util::stream::unfold(request_rx, |mut rx| async move {
        rx.recv().await.map(|chunk| {
            (
                Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(chunk)),
                rx,
            )
        })
    });
    let request_body = reqwest::Body::wrap(http_body_util::StreamBody::new(request_stream));

    let url = format!("https://{}/", server.addr());
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client builder");

    let mut res = client
        .post(&url)
        .version(http::Version::HTTP_3)
        .body(request_body)
        .send()
        .await
        .expect("response");

    assert_eq!(res.version(), http::Version::HTTP_3);
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    response_tx
        .send(bytes::Bytes::from_static(b"first"))
        .unwrap();
    let first = res
        .chunk()
        .await
        .ok()
        .flatten()
        .expect("missing first response chunk");
    assert_eq!(first, bytes::Bytes::from_static(b"first"));

    request_tx
        .send(bytes::Bytes::from_static(b"late request chunk"))
        .unwrap();
    drop(request_tx);

    response_tx
        .send(bytes::Bytes::from_static(b"second"))
        .unwrap();
    drop(response_tx);

    let second = res
        .chunk()
        .await
        .ok()
        .flatten()
        .expect("missing second response chunk");
    assert_eq!(second, bytes::Bytes::from_static(b"second"));
    assert!(res.chunk().await.expect("read response eof").is_none());
}

#[cfg(feature = "http3")]
#[tokio::test]
async fn http3_test_h3_stop_sending_before_response_internal_error() {
    // Order of payloads:
    // 1. Server: Response headers
    // 2. Server: STOP_SENDING with error
    // 3. Server: Response body chunk, ensures following happens after STOP_SENDING
    // 4. Client: Request close - returns error

    let (response_tx, response_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
    let response_rx = std::sync::Arc::new(std::sync::Mutex::new(Some(response_rx)));
    let server_response_rx = response_rx.clone();

    let server = server::Http3::new().build_with_stop_sending_before_response(
        move |_| {
            let server_response_rx = server_response_rx.clone();
            async move {
                let response_rx = server_response_rx.lock().unwrap().take().unwrap();
                let response_stream =
                    futures_util::stream::unfold(response_rx, |mut rx| async move {
                        rx.recv().await.map(|chunk| {
                            (
                                Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(chunk)),
                                rx,
                            )
                        })
                    });
                let response_body =
                    reqwest::Body::wrap(http_body_util::StreamBody::new(response_stream));
                http::Response::new(response_body)
            }
        },
        0x102,
    );

    let (request_tx, request_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
    let request_stream = futures_util::stream::unfold(request_rx, |mut rx| async move {
        rx.recv().await.map(|chunk| {
            (
                Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(chunk)),
                rx,
            )
        })
    });
    let request_body = reqwest::Body::wrap(http_body_util::StreamBody::new(request_stream));

    let url = format!("https://{}/", server.addr());
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client builder");

    let mut res = client
        .post(&url)
        .version(http::Version::HTTP_3)
        .body(request_body)
        .send()
        .await
        .expect("response");

    assert_eq!(res.version(), http::Version::HTTP_3);
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    response_tx
        .send(bytes::Bytes::from_static(b"first"))
        .expect("send first response chunk");
    let first = res
        .chunk()
        .await
        .ok()
        .flatten()
        .expect("missing first response chunk");
    assert_eq!(first, bytes::Bytes::from_static(b"first"));

    drop(request_tx);

    response_tx
        .send(bytes::Bytes::from_static(b"second"))
        .unwrap();
    drop(response_tx);

    // Response data and the upload error can arrive in either order. The error
    // must be observed before the body reports a successful end of stream.
    let err = loop {
        match res.chunk().await {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("upload error was lost at end of response"),
            Err(error) => break error,
        }
    };
    assert!(err.is_decode());
    let mut source = err.source();
    let mut found = false;
    while let Some(err) = source {
        if matches!(
            err.downcast_ref::<quiche::h3::Error>(),
            Some(quiche::h3::Error::TransportError(
                quiche::Error::StreamStopped(0x102)
            ))
        ) {
            found = true;
        }
        source = err.source();
    }
    assert!(found, "expected peer STOP_SENDING error");
}

#[cfg(feature = "http3")]
#[tokio::test]
async fn http3_test_reconnection() {
    let server = server::Http3::new().build(|_| async { http::Response::default() });
    let addr = server.addr();

    let url = format!("https://{}/", addr);
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .http3_max_idle_timeout(std::time::Duration::from_millis(20))
        .build()
        .expect("client builder");

    let res = client
        .post(&url)
        .version(http::Version::HTTP_3)
        .send()
        .await
        .expect("request");

    assert_eq!(res.version(), http::Version::HTTP_3);
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    drop(server);

    let err = client
        .get(&url)
        .version(http::Version::HTTP_3)
        .send()
        .await
        .unwrap_err();

    assert!(err.is_timeout(), "expected timeout: {err:?}");

    let server = server::Http3::new()
        .with_addr(addr)
        .build(|_| async { http::Response::default() });

    let res = client
        .post(&url)
        .version(http::Version::HTTP_3)
        .body("hello")
        .send()
        .await
        .expect("request");

    assert_eq!(res.version(), http::Version::HTTP_3);
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    drop(server);
}

#[cfg(all(feature = "http3", feature = "stream"))]
#[tokio::test]
async fn http3_request_stream() {
    use http_body_util::BodyExt;

    let server = server::Http3::new().build(move |req| async move {
        let reqb = req.collect().await.unwrap().to_bytes();
        assert_eq!(reqb, "hello world");
        http::Response::default()
    });

    let url = format!("https://{}", server.addr());
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter(vec![
        Ok::<_, std::convert::Infallible>("hello"),
        Ok::<_, std::convert::Infallible>(" "),
        Ok::<_, std::convert::Infallible>("world"),
    ]));

    let res = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client builder")
        .post(url)
        .version(http::Version::HTTP_3)
        .body(body)
        .send()
        .await
        .expect("request");

    assert_eq!(res.version(), http::Version::HTTP_3);
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}

#[cfg(all(feature = "http3", feature = "stream"))]
#[tokio::test]
async fn http3_request_stream_error() {
    use http_body_util::BodyExt;

    let server = server::Http3::new().build(move |req| async move {
        // HTTP/3 response can start and finish before the entire request body has been received.
        // To avoid prematurely terminating the session, collect full request body before responding.
        let _ = req.collect().await;

        http::Response::default()
    });

    let url = format!("https://{}", server.addr());
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter(vec![
        Ok::<_, std::io::Error>("first chunk"),
        Err::<_, std::io::Error>(std::io::Error::other("oh no!")),
    ]));

    let res = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client builder")
        .post(url)
        .version(http::Version::HTTP_3)
        .body(body)
        .send()
        .await;

    let err = res.unwrap_err();
    assert!(err.is_request());
    let err = err
        .source()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<reqwest::Error>()
        .unwrap();
    assert!(err.is_body());
}

#[tokio::test]
async fn http3_verified_tls_large_body_and_cancellation() {
    use http_body_util::BodyExt;
    let server = server::Http3::new().build(|req| async move {
        let body = req.collect().await.unwrap().to_bytes();
        http::Response::new(reqwest::Body::from(body))
    });
    let ca = reqwest::Certificate::from_pem(include_bytes!("support/boring/ca.pem")).unwrap();
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .no_proxy()
        .tls_certs_only([ca])
        .resolve("localhost", server.addr())
        .http3_stream_receive_window(32768)
        .http3_conn_receive_window(65536)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let url = format!("https://localhost:{}/", server.addr().port());
    let body = vec![0x42; 1024 * 1024];
    let mut response = client
        .post(&url)
        .version(http::Version::HTTP_3)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    // Pause the consumer long enough to fill its bounded receive channel.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(!response.chunk().await.unwrap().unwrap().is_empty());
    drop(response);
    let response = client
        .post(&url)
        .version(http::Version::HTTP_3)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes().await.unwrap(), body);
}

#[tokio::test]
async fn http3_tls13_required() {
    assert!(reqwest::Client::builder()
        .http3_prior_knowledge()
        .tls_version_max(reqwest::tls::Version::TLS_1_2)
        .build()
        .is_err());
}

#[tokio::test]
async fn http3_goaway_reconnects_without_losing_response() {
    let server = server::Http3::new()
        .with_goaway()
        .build(|_| async { http::Response::new(reqwest::Body::from("draining")) });
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    for _ in 0..3 {
        let response = client
            .get(format!("https://{}/", server.addr()))
            .version(http::Version::HTTP_3)
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "draining");
    }
}

#[tokio::test]
async fn http3_session_resumption_with_early_data() {
    let server = server::Http3::new()
        .build(|_| async { http::Response::new(reqwest::Body::from("resumed")) });
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .tls_early_data(true)
        .pool_idle_timeout(std::time::Duration::ZERO)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("https://{}/", server.addr());
    for round in 0..3 {
        let response = client
            .get(&url)
            .version(http::Version::HTTP_3)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.headers()["x-test-session-reused"],
            if round == 0 { "false" } else { "true" }
        );
        assert_eq!(response.text().await.unwrap(), "resumed");
    }
}
