//! Repairs the HTTP/2 `:authority` the runner sends over a unix socket.
//!
//! forgejo-runner dials a unix-socket plugin as `passthrough:///<path>`, so
//! grpc-go puts the socket path (`/run/ember/ember.sock`) in `:authority`.
//! That is not a valid authority, and Rust's h2 rejects such requests with
//! PROTOCOL_ERROR. This shim sits between the socket and the gRPC server:
//! it re-encodes each request's header block, replacing an invalid
//! authority with `localhost`, and copies every other frame unchanged.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HEADERS: u8 = 0x1;
const CONTINUATION: u8 = 0x9;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;
const MAX_FRAME: usize = 16384; // the HTTP/2 default; h2 never lowers it

/// The server side of a repaired connection.
pub struct Conn(DuplexStream);

impl tonic::transport::server::Connected for Conn {
    type ConnectInfo = ();
    fn connect_info(&self) {}
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Wraps a client connection; the returned end goes to the gRPC server.
pub fn wrap<S>(client: S) -> Conn
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (server_end, ours) = tokio::io::duplex(256 << 10);
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut ours_r, mut ours_w) = tokio::io::split(ours);
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut ours_r, &mut client_w).await;
        let _ = client_w.shutdown().await;
    });
    tokio::spawn(async move {
        let _ = rewrite(&mut client_r, &mut ours_w).await;
        let _ = ours_w.shutdown().await;
    });
    Conn(server_end)
}

/// Copies client frames to the server, repairing header blocks.
pub async fn rewrite(
    r: &mut (impl AsyncRead + Unpin),
    w: &mut (impl AsyncWrite + Unpin),
) -> io::Result<()> {
    let mut preface = [0u8; 24];
    r.read_exact(&mut preface).await?;
    w.write_all(&preface).await?;
    if preface != PREFACE {
        // Not HTTP/2 with prior knowledge: let the server reject it.
        tokio::io::copy(r, w).await?;
        return Ok(());
    }
    let mut decoder = hpack::Decoder::new();
    let mut encoder = hpack::Encoder::new();
    loop {
        let Some((kind, flags, stream, payload)) = read_frame(r).await? else {
            return Ok(());
        };
        if kind != HEADERS {
            write_frame(w, kind, flags, stream, &payload).await?;
            continue;
        }
        let mut block = header_fragment(flags, &payload)?;
        let mut end = flags & END_HEADERS != 0;
        while !end {
            let (k, f, s, p) = read_frame(r)
                .await?
                .ok_or_else(|| bad("eof inside a header block"))?;
            if k != CONTINUATION || s != stream {
                return Err(bad("expected CONTINUATION"));
            }
            block.extend_from_slice(&p);
            end = f & END_HEADERS != 0;
        }
        let mut headers = decoder
            .decode(&block)
            .map_err(|e| bad(&format!("hpack: {e:?}")))?;
        for (name, value) in headers.iter_mut() {
            if name == b":authority" && http::uri::Authority::try_from(value.as_slice()).is_err() {
                *value = b"localhost".to_vec();
            }
        }
        let encoded = encoder.encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        let mut chunks = encoded.chunks(MAX_FRAME).peekable();
        let mut first = true;
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            let mut f = if last { END_HEADERS } else { 0 };
            let k = if first {
                f |= flags & END_STREAM;
                HEADERS
            } else {
                CONTINUATION
            };
            write_frame(w, k, f, stream, chunk).await?;
            first = false;
        }
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// The header block fragment of a HEADERS frame, without padding and
/// priority fields (the rewritten frame carries neither).
fn header_fragment(flags: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut p = payload;
    let mut pad = 0;
    if flags & PADDED != 0 {
        pad = *p.first().ok_or_else(|| bad("short frame"))? as usize;
        p = &p[1..];
    }
    if flags & PRIORITY != 0 {
        p = p.get(5..).ok_or_else(|| bad("short frame"))?;
    }
    let len = p.len().checked_sub(pad).ok_or_else(|| bad("bad padding"))?;
    Ok(p[..len].to_vec())
}

async fn read_frame(
    r: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<(u8, u8, u32, Vec<u8>)>> {
    let mut h = [0u8; 9];
    match r.read_exact(&mut h).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
    if len > 1 << 24 {
        return Err(bad("frame too large"));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    let stream = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
    Ok(Some((h[3], h[4], stream, payload)))
}

async fn write_frame(
    w: &mut (impl AsyncWrite + Unpin),
    kind: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
) -> io::Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    let mut h = [len[1], len[2], len[3], kind, flags, 0, 0, 0, 0];
    h[5..].copy_from_slice(&stream.to_be_bytes());
    w.write_all(&h).await?;
    w.write_all(payload).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replaces_a_socket_path_authority() {
        let mut enc = hpack::Encoder::new();
        let block = enc.encode(vec![
            (&b":method"[..], &b"POST"[..]),
            (b":scheme", b"http"),
            (b":authority", b"/run/ember/ember.sock"),
            (b":path", b"/grpc.health.v1.Health/Check"),
        ]);
        let mut input = PREFACE.to_vec();
        // A padded HEADERS frame split by a CONTINUATION, then a DATA frame.
        let (a, b) = block.split_at(block.len() / 2);
        let mut first = vec![2u8];
        first.extend_from_slice(a);
        first.extend_from_slice(&[0, 0]);
        for (kind, flags, payload) in [
            (HEADERS, PADDED, first),
            (CONTINUATION, END_HEADERS, b.to_vec()),
            (0x0, END_STREAM, b"hi".to_vec()),
        ] {
            let len = (payload.len() as u32).to_be_bytes();
            input.extend_from_slice(&[len[1], len[2], len[3], kind, flags, 0, 0, 0, 1]);
            input.extend_from_slice(&payload);
        }
        let mut out = Vec::new();
        rewrite(&mut &input[..], &mut out).await.unwrap();
        assert_eq!(&out[..24], PREFACE);
        let mut r = &out[24..];
        let (kind, flags, stream, payload) = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(
            (kind, flags & END_HEADERS, stream),
            (HEADERS, END_HEADERS, 1)
        );
        let headers = hpack::Decoder::new().decode(&payload).unwrap();
        let authority = headers.iter().find(|(n, _)| n == b":authority").unwrap();
        assert_eq!(authority.1, b"localhost");
        let (kind, _, _, payload) = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!((kind, payload.as_slice()), (0x0, &b"hi"[..]));
    }
}
