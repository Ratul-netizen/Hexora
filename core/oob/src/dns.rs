//! The collaborator's DNS listener — catches lookups a target only *resolves* (OOB.b).
//!
//! Some blind vulnerabilities never open a connection: a `nslookup <token>.domain` from a
//! command injection, a library that resolves a hostname behind a firewall that blocks the
//! HTTP. The DNS query still leaves the target, so the collaborator answers A queries (with an
//! address the tester chooses, so a resolved payload can then be connected to) and records the
//! lookup under its token.

use std::net::Ipv4Addr;

use tokio::net::UdpSocket;

use hexora_types::error::{HexoraError, NetworkError, Result};

use crate::server::Store;
use crate::Interaction;

/// Runs the DNS listener on `addr`, answering A queries with `answer_ip` and recording the
/// token-bearing lookups into `store`.
pub(crate) async fn run_dns(addr: &str, store: Store, answer_ip: Ipv4Addr) -> Result<()> {
    let socket = UdpSocket::bind(addr)
        .await
        .map_err(|e| HexoraError::invalid_input("dns", format!("{addr}: {e}")))?;
    if let Ok(local) = socket.local_addr() {
        tracing::info!(%local, "collaborator DNS listening");
    }

    let mut buf = [0u8; 512];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(pair) => pair,
            Err(e) => {
                return Err(HexoraError::Network(NetworkError::Io(e.to_string())));
            }
        };
        if let Some((qname, response)) = respond(&buf[..len], answer_ip) {
            if let Some(token) = token_of_qname(&qname) {
                store.record(Interaction {
                    token,
                    protocol: "dns".into(),
                    method: "QUERY".into(),
                    path: qname.clone(),
                    host: qname,
                    source: peer.ip().to_string(),
                    at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                });
            }
            let _ = socket.send_to(&response, peer).await;
        }
    }
}

/// Parses a query and builds a response, returning `(qname, response bytes)`. `None` on a
/// malformed or non-question packet — a hostile datagram must not panic the listener.
fn respond(query: &[u8], answer_ip: Ipv4Addr) -> Option<(String, Vec<u8>)> {
    if query.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount < 1 {
        return None;
    }

    let (qname, after) = parse_qname(query, 12)?;
    if after + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[after], query[after + 1]]);
    let question_end = after + 4;
    let answer_a = qtype == 1; // A record

    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[0..2]); // transaction id, echoed
    response.extend_from_slice(&[0x81, 0x80]); // flags: response, recursion available
    response.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
    response.extend_from_slice(&(u16::from(answer_a)).to_be_bytes()); // ancount
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // nscount, arcount
    response.extend_from_slice(&query[12..question_end]); // echo the question

    if answer_a {
        response.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to the question at offset 12
        response.extend_from_slice(&[0x00, 0x01]); // type A
        response.extend_from_slice(&[0x00, 0x01]); // class IN
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60s
        response.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
        response.extend_from_slice(&answer_ip.octets());
    }

    Some((qname, response))
}

/// Reads a QNAME (a sequence of length-prefixed labels ending in a zero byte), returning the
/// dotted name and the offset just past the terminator. Bounded and compression-free, as a
/// question section is.
fn parse_qname(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut i = start;
    loop {
        let len = *data.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointers do not appear in a question
        }
        i += 1;
        let end = i.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&data[i..end]).to_string());
        i = end;
        if labels.len() > 127 {
            return None;
        }
    }
    Some((labels.join("."), i))
}

/// The token is the leftmost label of the queried name, when it is token-shaped.
fn token_of_qname(qname: &str) -> Option<String> {
    let leftmost = qname.split('.').next().unwrap_or("");
    (leftmost.len() >= 16).then(|| leftmost.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal DNS A-query for `name`.
    fn query_for(name: &str) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
        q
    }

    #[test]
    fn a_query_is_parsed_and_answered() {
        let token = crate::fresh_token();
        let name = format!("{token}.oob.example");
        let (qname, response) = respond(&query_for(&name), Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        assert_eq!(qname, name);
        // Response echoes the id, has one answer, and ends with the answer IP.
        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1); // ancount
        assert_eq!(&response[response.len() - 4..], &[10, 0, 0, 1]);
        assert_eq!(token_of_qname(&qname).as_deref(), Some(token.as_str()));
    }

    #[test]
    fn a_malformed_packet_is_ignored() {
        assert!(respond(&[0x00, 0x01], Ipv4Addr::LOCALHOST).is_none());
        assert!(respond(&[], Ipv4Addr::LOCALHOST).is_none());
    }
}
