use super::{Event, Server};
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use quiche::h3::NameValue;
use std::{collections::HashMap, future::Future, net::SocketAddr, sync::mpsc as std_mpsc};
use tokio::sync::{mpsc, oneshot};

type Incoming = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;
type Frame = Result<hyper::body::Frame<Bytes>, std::io::Error>;

#[derive(Debug, Default)]
pub struct Http3 {
    addr: Option<SocketAddr>,
    goaway: bool,
}
impl Http3 {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_goaway(mut self) -> Self {
        self.goaway = true;
        self
    }
    pub fn with_addr(mut self, addr: SocketAddr) -> Self {
        self.addr = Some(addr);
        self
    }
    pub fn build<F, Fut>(self, func: F) -> Server
    where
        F: Fn(http::Request<Incoming>) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = http::Response<reqwest::Body>> + Send + 'static,
    {
        self.build_server(func, None)
    }
    pub fn build_with_stop_sending_before_response<F, Fut>(self, func: F, code: u64) -> Server
    where
        F: Fn(http::Request<Incoming>) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = http::Response<reqwest::Body>> + Send + 'static,
    {
        self.build_server(func, Some(code))
    }
    fn build_server<F, Fut>(self, func: F, stop: Option<u64>) -> Server
    where
        F: Fn(http::Request<Incoming>) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = http::Response<reqwest::Body>> + Send + 'static,
    {
        let goaway = self.goaway;
        let socket =
            std::net::UdpSocket::bind(self.addr.unwrap_or_else(|| "[::1]:0".parse().unwrap()))
                .unwrap();
        socket.set_nonblocking(true).unwrap();
        let addr = socket.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let (panic_tx, panic_rx) = std_mpsc::channel();
        let (events_tx, events_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let socket = tokio::net::UdpSocket::from_std(socket).unwrap();
                let mut tls = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
                tls.set_certificate(&boring::x509::X509::from_pem(include_bytes!("boring/server.pem")).unwrap()).unwrap();
                tls.set_private_key(&boring::pkey::PKey::private_key_from_pem(include_bytes!("boring/server.key.pem")).unwrap()).unwrap();
                let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls).unwrap();
                config.set_application_protos(&[b"h3"]).unwrap();
                config.set_max_idle_timeout(10000);
                config.enable_early_data();
                config.set_initial_max_data(10_000_000);
                config.set_initial_max_stream_data_bidi_local(1_000_000);
                config.set_initial_max_stream_data_bidi_remote(1_000_000);
                config.set_initial_max_stream_data_uni(1_000_000);
                config.set_initial_max_streams_bidi(100);
                config.set_initial_max_streams_uni(100);
                config.set_max_send_udp_payload_size(1350);
                let mut connections: HashMap<SocketAddr, Peer> = HashMap::new();
                let mut buf = vec![0; 65535];
                let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(1));
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        _ = tick.tick() => {
                            for peer in connections.values_mut() {
                                if peer.conn.timeout().is_some_and(|d| d.is_zero()) { peer.conn.on_timeout(); }
                            }
                        }
                        Some(command) = rx.recv() => match command {
                            Command::Response(remote, id, response) => {
                                let peer = connections.get_mut(&remote).unwrap();
                                let (parts, mut body) = response.into_parts();
                                let mut headers = vec![quiche::h3::Header::new(b":status", parts.status.as_str().as_bytes()), quiche::h3::Header::new(b"x-test-session-reused", if peer.conn.as_mut().session_reused() { b"true" } else { b"false" })];
                                for (name, value) in &parts.headers { headers.push(quiche::h3::Header::new(name.as_str().as_bytes(), value.as_bytes())); }
                                peer.h3.as_mut().unwrap().send_response(&mut peer.conn, id, &headers, false).unwrap();
                                if goaway { peer.h3.as_mut().unwrap().send_goaway(&mut peer.conn, id + 4).unwrap(); }
                                let tx = tx.clone();
                                tokio::spawn(async move {
                                    while let Some(Ok(frame)) = body.frame().await {
                                        if let Ok(data) = frame.into_data() {
                                            let (ack, rx) = oneshot::channel();
                                            let _ = tx.send(Command::Data(remote, id, data, false, ack));
                                            if rx.await.is_err() { return; }
                                        }
                                    }
                                    let (ack, _) = oneshot::channel();
                                    let _ = tx.send(Command::Data(remote, id, Bytes::new(), true, ack));
                                });
                            }
                            Command::Data(remote, id, bytes, fin, ack) => { if let Some(peer) = connections.get_mut(&remote) { peer.output.insert(id, (bytes, fin, ack)); } }
                        },
                        result = socket.recv_from(&mut buf) => {
                            let (len, remote) = result.unwrap();
                            if let std::collections::hash_map::Entry::Vacant(e) = connections.entry(remote) {
                                let header = quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN).unwrap();
                                if header.ty != quiche::Type::Initial { continue; }
                                let mut id = [0; quiche::MAX_CONN_ID_LEN]; boring::rand::rand_bytes(&mut id).unwrap();
                                let conn = quiche::accept(&quiche::ConnectionId::from_ref(&id), None, addr, remote, &mut config).unwrap();
                                e.insert(Peer { conn, h3: None, input: HashMap::new(), output: HashMap::new() });
                            }
                            let peer = connections.get_mut(&remote).unwrap();
                            let _ = peer.conn.recv(&mut buf[..len], quiche::RecvInfo { from: remote, to: addr });
                        }
                    }
                    for (&remote, peer) in &mut connections {
                        if peer.conn.is_established() && peer.h3.is_none() { peer.h3 = Some(quiche::h3::Connection::with_transport(&mut peer.conn, &quiche::h3::Config::new().unwrap()).unwrap()); }
                        if let Some(h3) = &mut peer.h3 {
                            loop {
                                match h3.poll(&mut peer.conn) {
                                    Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                                        let mut request = http::Request::builder().version(http::Version::HTTP_3);
                                        for header in list {
                                            match header.name() {
                                                b":method" => request = request.method(header.value()),
                                                b":path" => request = request.uri(header.value()),
                                                b":scheme" | b":authority" => {},
                                                _ => request = request.header(header.name(), header.value()),
                                            }
                                        }
                                        let (body_tx, body_rx) = mpsc::unbounded_channel::<Frame>();
                                        peer.input.insert(id, body_tx);
                                        if let Some(code) = stop { let _ = peer.conn.stream_shutdown(id, quiche::Shutdown::Read, code); peer.input.remove(&id); }
                                        let stream = futures_util::stream::unfold(body_rx, |mut rx| async { rx.recv().await.map(|item| (item, rx)) });
                                        let request = request.body(StreamBody::new(stream).boxed()).unwrap();
                                        let func = func.clone(); let tx = tx.clone();
                                        tokio::spawn(async move { let response = func(request).await; let _ = tx.send(Command::Response(remote, id, response)); });
                                    }
                                    Ok((id, quiche::h3::Event::Data)) => {
                                        let mut data = vec![0; 65536];
                                        while let Ok(n) = h3.recv_body(&mut peer.conn, id, &mut data) {
                                            if let Some(tx) = peer.input.get(&id) { let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::copy_from_slice(&data[..n])))); }
                                        }
                                    }
                                    Ok((id, quiche::h3::Event::Finished | quiche::h3::Event::Reset(_))) => { peer.input.remove(&id); }
                                    Ok(_) => {}, Err(quiche::h3::Error::Done) => break, Err(e) => panic!("H3 test server: {e}"),
                                }
                            }
                            let ids: Vec<_> = peer.output.keys().copied().collect();
                            for id in ids {
                                let (mut data, fin, ack) = peer.output.remove(&id).unwrap();
                                match h3.send_body(&mut peer.conn, id, &data, fin) {
                                    Ok(n) => {
                                        data = data.slice(n..);
                                        if data.is_empty() { let _ = ack.send(()); if fin { let _ = events_tx.send(Event::ConnectionClosed); } }
                                        else { peer.output.insert(id, (data, fin, ack)); }
                                    }
                                    Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => { peer.output.insert(id, (data, fin, ack)); }
                                    Err(_) => {},
                                }
                            }
                        }
                        let mut out = [0; 1350];
                        while let Ok((n, info)) = peer.conn.send(&mut out) { socket.send_to(&out[..n], info.to).await.unwrap(); }
                    }
                    connections.retain(|_, peer| !peer.conn.is_closed());
                }
                let _ = panic_tx.send(());
            });
        });
        Server {
            addr,
            panic_rx,
            events_rx,
            shutdown_tx: Some(shutdown_tx),
        }
    }
}
enum Command {
    Response(SocketAddr, u64, http::Response<reqwest::Body>),
    Data(SocketAddr, u64, Bytes, bool, oneshot::Sender<()>),
}
struct Peer {
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    input: HashMap<u64, mpsc::UnboundedSender<Frame>>,
    output: HashMap<u64, (Bytes, bool, oneshot::Sender<()>)>,
}
