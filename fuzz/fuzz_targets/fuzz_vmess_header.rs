#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let uuid = uuid::Uuid::new_v4();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut cursor = Cursor::new(data.to_vec());
        let _ = flux_protocol::vmess::VmessProtocol::read_request_header(&mut cursor, &[uuid]).await;
    });
});
