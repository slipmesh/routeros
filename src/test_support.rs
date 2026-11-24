//! Fixtures shared by every module's tests. Key material is generated here and nowhere else: a
//! key pasted into a test from a live config is published with the repository.

use sliplib_secrets::wireguard::encode_key;

/// A WireGuard-shaped key made of `label` repeated to 32 bytes: distinct per label, the same on
/// every run, and plain text once decoded, so it can't be mistaken for a real one.
pub fn wg_key(label: &str) -> String {
    let mut bytes = [0u8; 32];
    for (b, l) in bytes.iter_mut().zip(label.bytes().cycle()) {
        *b = l;
    }
    encode_key(&bytes)
}
