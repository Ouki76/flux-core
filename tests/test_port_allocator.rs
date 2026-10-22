//! Tests for the shared port allocator.
//!
//! These live in their own binary on purpose: when they sat inside
//! `tests/common/mod.rs` they were compiled into *every* integration test binary
//! (24 of them), so the suite total counted them 24 times and the number stopped
//! meaning anything.

mod common;

use common::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};

/// The probe must reject a port a live listener holds **even with
/// `SO_REUSEPORT`**, which defeats a bare bind probe. This is the case that
/// silently handed out an occupied port and produced `AddrInUse` failures.
///
/// Deliberately tests `port_is_free` and not `get_free_tcp_port`: the latter
/// mutates a process-global counter that other tests in the same binary are
/// using concurrently, so a test that nudged it would corrupt their ports.
///
/// The second half necessarily races the rest of the host: after `drop(sock)`
/// another process (a second suite, an unrelated server) may legitimately
/// take that ephemeral port before the re-probe, which says nothing about the
/// probe. Retry on a fresh port instead of failing on someone else's bind.
#[tokio::test]
async fn a_reuseport_listener_is_not_considered_free() {
    use socket2::{Domain, Protocol, Socket, Type};

    for _ in 0..5 {
        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        sock.set_reuse_address(true).unwrap();
        #[cfg(all(unix, not(target_os = "solaris")))]
        let _ = sock.set_reuse_port(true);
        sock.bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        sock.listen(1).unwrap();
        let taken = sock.local_addr().unwrap().as_socket().unwrap().port();

        assert!(
            !port_is_free(taken).await,
            "a port with a SO_REUSEPORT listener was reported free"
        );
        drop(sock);

        // Once the squatter is gone the same port must be reported free again.
        if !port_is_free(taken).await {
            // Taken by someone else in the gap: not this probe's fault.
            eprintln!("port {taken} was claimed by another process after drop; retrying");
            continue;
        }
        return;
    }
    panic!("the port stayed busy after the listener was dropped, five times in a row");
}

/// The allocator's advance must be a single atomic step, and it must stay
/// inside the process's block.
///
/// The previous `fetch_add` + separate `store()` could hand the base port out
/// twice: thread A stores the base, thread B (already past the range check)
/// stores the base again *after* A took it. Exercised on a private counter so
/// the shared one is untouched.
#[test]
fn advancing_through_the_range_never_repeats_a_port() {
    let base = block_start(0);
    let counter = AtomicU16::new(0); // "not placed yet"
    assert_eq!(next_candidate_port_from(&counter, base), base);
    assert_eq!(next_candidate_port_from(&counter, base), base + 1);

    // Sit one below the end of the block: the next two values must be the
    // last port of the block and then the block base again — never the base
    // twice, never a port outside the block.
    counter.store(base + PORT_BLOCK_SIZE - 1, Ordering::Relaxed);
    assert_eq!(
        next_candidate_port_from(&counter, base),
        base + PORT_BLOCK_SIZE - 1
    );
    assert_eq!(next_candidate_port_from(&counter, base), base);
    assert_eq!(next_candidate_port_from(&counter, base), base + 1);

    // A cursor left at or past the end must also wrap instead of returning
    // an out-of-block (possibly ephemeral-range) port.
    counter.store(base + PORT_BLOCK_SIZE, Ordering::Relaxed);
    assert_eq!(next_candidate_port_from(&counter, base), base);
    counter.store(u16::MAX, Ordering::Relaxed);
    assert_eq!(next_candidate_port_from(&counter, base), base);
}

/// A block is exclusive to one process: the whole point of the reservation.
///
/// Uses a private abstract-socket name rather than a real block, so the
/// assertions are deterministic even while other suites run on this host.
#[test]
fn a_port_block_cannot_be_claimed_twice() {
    let name = format!(
        "flux-core-test-ports-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let first = match claim_abstract_socket(&name) {
        Ok(Some(fd)) => fd,
        Ok(None) => panic!("a fresh abstract name must not already be claimed"),
        Err(e) => panic!("cannot claim an abstract socket on this platform: {e}"),
    };

    // A second claim on the same name from the same host must be refused —
    // this is what stops two suites from allocating the same ports.
    match claim_abstract_socket(&name) {
        Ok(None) => {}
        Ok(Some(_)) => panic!("the block was handed out twice while it was still claimed"),
        Err(e) => panic!("re-claiming the block failed: {e}"),
    }

    // And it must be available again the moment the claim is released.
    drop(first);
    match claim_abstract_socket(&name) {
        Ok(Some(_)) => {}
        Ok(None) => panic!("the block stayed claimed after its holder released it"),
        Err(e) => panic!("re-claiming the released block failed: {e}"),
    }
}

/// Every block starts on a block boundary and the blocks tile the range.
#[test]
fn blocks_tile_the_test_range() {
    assert_eq!(block_start(0), TEST_PORT_BASE);
    assert_eq!(block_start(PORT_BLOCKS), TEST_PORT_MAX);
    for index in 0..PORT_BLOCKS {
        let start = block_start(index);
        assert!(
            (TEST_PORT_BASE..TEST_PORT_MAX).contains(&start),
            "block {index} starts at {start}, outside the test range"
        );
        assert!(
            start + PORT_BLOCK_SIZE <= TEST_PORT_MAX,
            "block {index} runs past the test range"
        );
    }
}

/// `/proc/net/*` rows must be decoded correctly, because the whole diagnosis
/// depends on the port column being read right.
#[test]
fn proc_net_rows_are_decoded() {
    // Verbatim shape of /proc/net/tcp on Linux 6.x (whitespace-trimmed).
    let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
     0: 0100007F:2EE0 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 3270269 1 0 0 10 0\n\
     1: 0100007F:1F90 0A0A0A0A:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 3270270 1 0 0 10 0\n";
    let rows = parse_net_table("tcp", table);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].local_ip, "127.0.0.1");
    assert_eq!(rows[0].local_port, 12_000); // 0x2EE0
    assert_eq!(rows[0].state, "LISTEN");
    assert_eq!(rows[0].uid, 1000);
    assert_eq!(rows[0].inode, 3_270_269);
    assert_eq!(rows[1].local_port, 8080); // 0x1F90
    assert_eq!(rows[1].state, "ESTABLISHED");

    assert_eq!(decode_hex_ip("0100007F"), "127.0.0.1");
    assert_eq!(decode_hex_ip("00000000"), "0.0.0.0");
    // A 16-byte v6 address decodes to four groups of little-endian words.
    assert_eq!(
        decode_hex_ip("00000000000000000000000000000000"),
        "0000:0000:0000:0000:0000:0000:0000:0000"
    );
    assert_eq!(decode_hex_ip("not-hex"), "not-hex");
}

/// End-to-end check of the failure report: a port this process itself holds
/// must be named as occupied, attributed to this pid, and pinned to the
/// configured inbound that declares it.
#[test]
fn the_failure_report_names_the_listener_and_the_holder() {
    // A plain listener (no SO_REUSEPORT) so that a second bind fails the way
    // flux's would against a foreign squatter.
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = squatter.local_addr().unwrap().port();
    let config = format!(
        r#"{{"inbounds":[{{"tag":"flux-vless-in","carrier":{{"type":"tcp","listen":"127.0.0.1","listen_port":{port}}},"protocol":{{"type":"vless"}}}}],"outbounds":[]}}"#
    );

    let report = diagnose_bind_failure(&config, port, "Io(Os { code: 98, kind: AddrInUse })");

    assert!(
        report.contains("configured[0] kind=inbound tag='flux-vless-in'"),
        "report did not identify the inbound:\n{report}"
    );
    assert!(
        report.contains("OCCUPIED"),
        "report did not classify the held port as occupied:\n{report}"
    );
    assert!(
        report.contains("THIS PROCESS"),
        "report did not attribute the holder to this pid:\n{report}"
    );
    assert!(
        report.contains("the inbound that failed is configured[0] tag='flux-vless-in'"),
        "report did not name the failing inbound:\n{report}"
    );
    assert!(
        report.contains("NOT handed out by this process's allocator"),
        "report did not state that the port bypassed the allocator:\n{report}"
    );

    // A port nothing holds must be reported free, and the report must say
    // so rather than invent a holder.
    let quiet = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let quiet_port = quiet.local_addr().unwrap().port();
    drop(quiet);
    let quiet_config = format!(
        r#"{{"inbounds":[{{"tag":"quiet-in","carrier":{{"type":"tcp","listen":"127.0.0.1","listen_port":{quiet_port}}},"protocol":{{"type":"vless"}}}}],"outbounds":[]}}"#
    );
    let free_report = diagnose_bind_failure(&quiet_config, quiet_port, "Io(Os { code: 98 })");
    assert!(
        free_report.contains("no socket currently has local port"),
        "report invented a holder for a free port:\n{free_report}"
    );
}
