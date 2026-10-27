//! Fixtures shared by every module's tests. Key material is generated here and nowhere else: a
//! key pasted into a test from a live config is published with the repository.

use base64::Engine as _;

/// Base64 of 32 bytes - the wire form of a WireGuard key.
pub fn encode_wg_key(bytes: [u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A WireGuard-shaped key made of `label` repeated to 32 bytes: distinct per label, the same on
/// every run, and plain text once decoded, so it can't be mistaken for a real one.
pub fn wg_key(label: &str) -> String {
    let mut bytes = [0u8; 32];
    for (b, l) in bytes.iter_mut().zip(label.bytes().cycle()) {
        *b = l;
    }
    encode_wg_key(bytes)
}
