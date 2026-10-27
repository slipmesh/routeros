//! Fixtures shared by every module's tests. Key material is generated here and nowhere else: a
//! key pasted into a test from a live config is published with the repository, and gitleaks can't
//! tell a WireGuard key from any other base64 string.

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

fn is_key_literal(quoted: &str) -> bool {
    quoted.len() == 44
        && quoted.ends_with('=')
        && quoted[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

#[test]
fn no_key_literal_outside_this_module() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("src");
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name() == Some("test_support.rs".as_ref()) {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            if line.split('"').any(is_key_literal) {
                let shown = path.strip_prefix(root).unwrap_or(&path);
                found.push(format!("{}:{}", shown.display(), n + 1));
            }
        }
    }
    assert!(
        found.is_empty(),
        "key-shaped literals, use test_support::wg_key: {found:#?}"
    );
}

#[test]
fn keys_differ_per_label_and_have_the_wire_shape() {
    assert_ne!(wg_key("node-a"), wg_key("node-b"));
    assert_eq!(wg_key("node-a"), wg_key("node-a"));
    assert!(is_key_literal(&wg_key("node-a")));
}
