//! Turning captured bytes into something a window can show.
//!
//! # Why this is not just `String::from_utf8_lossy`
//!
//! A captured body is arbitrary bytes of arbitrary size. Three things go wrong if the
//! UI is handed them raw:
//!
//! * **Size.** A 400 MB download serialized through IPC and rendered into a DOM node
//!   freezes the window. Bodies are truncated here, and the truncation is *reported*
//!   so the UI never implies it is showing everything.
//! * **Binary.** An image or an archive rendered as lossy UTF-8 is a screen of
//!   replacement characters that hides whatever was interesting. Binary is detected
//!   and offered as hex instead.
//! * **Honesty.** Lossy decoding silently replaces malformed sequences, which for a
//!   security tool means the bytes on screen are not the bytes on the wire. Anything
//!   that is not valid UTF-8 is shown as hex, where every byte is exact.
//!
//! The rule throughout: it is fine to show less than the whole body, and never fine to
//! show something different from it.

use serde::Serialize;

/// How much of a body the UI is given.
///
/// A window renders a few screens at a time; everything past that costs IPC bandwidth
/// and DOM nodes for bytes nobody reads. The full body is always still one command
/// away, and on disk regardless.
pub const PREVIEW_LIMIT: usize = 512 * 1024;

/// Bytes inspected when deciding whether a body is binary.
///
/// Enough to catch a header and any early NUL, cheap enough to run on every row.
const SNIFF_WINDOW: usize = 8 * 1024;

/// How a body should be displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Rendering {
    /// Valid UTF-8; shown as text.
    Text,
    /// Not text, or not valid UTF-8; shown as hex so every byte is exact.
    Binary,
    /// There was no body.
    Empty,
}

/// A body prepared for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BodyPreview {
    /// How to display it.
    pub rendering: Rendering,
    /// The text, or the hex dump, depending on `rendering`.
    pub content: String,
    /// The body's real size in bytes, whatever was sent here.
    pub total_bytes: usize,
    /// Whether `content` covers less than the whole body.
    pub truncated: bool,
}

impl BodyPreview {
    /// Prepares a body for display.
    pub fn of(body: &[u8]) -> Self {
        if body.is_empty() {
            return Self {
                rendering: Rendering::Empty,
                content: String::new(),
                total_bytes: 0,
                truncated: false,
            };
        }

        let total_bytes = body.len();
        let truncated = total_bytes > PREVIEW_LIMIT;
        let shown = &body[..total_bytes.min(PREVIEW_LIMIT)];

        if looks_binary(body) {
            return Self {
                rendering: Rendering::Binary,
                content: hex_dump(shown),
                total_bytes,
                truncated,
            };
        }

        match std::str::from_utf8(shown) {
            Ok(text) => Self {
                rendering: Rendering::Text,
                content: text.to_string(),
                total_bytes,
                truncated,
            },
            // A truncation can land mid-character, which is not the body being binary.
            // Back off to the last complete character rather than declaring an
            // ordinary UTF-8 document unreadable.
            Err(e) if truncated && e.valid_up_to() > 0 => {
                let valid = &shown[..e.valid_up_to()];
                Self {
                    rendering: Rendering::Text,
                    content: String::from_utf8_lossy(valid).into_owned(),
                    total_bytes,
                    truncated: true,
                }
            }
            // Genuinely not UTF-8. Hex, because lossy decoding would put characters on
            // screen that were never on the wire.
            Err(_) => Self {
                rendering: Rendering::Binary,
                content: hex_dump(shown),
                total_bytes,
                truncated,
            },
        }
    }
}

/// Whether a body should be treated as binary.
///
/// A NUL byte is the signal. Text formats do not contain them and essentially every
/// binary format does, which makes it both cheap and accurate — far more so than
/// trusting `Content-Type`, which is frequently wrong and is attacker-influenced on
/// exactly the responses a tester cares about.
fn looks_binary(body: &[u8]) -> bool {
    body[..body.len().min(SNIFF_WINDOW)].contains(&0)
}

/// Renders bytes as an offset/hex/ASCII dump.
fn hex_dump(bytes: &[u8]) -> String {
    const PER_LINE: usize = 16;

    let mut out = String::with_capacity(bytes.len() * 4);
    for (index, chunk) in bytes.chunks(PER_LINE).enumerate() {
        out.push_str(&format!("{:08x}  ", index * PER_LINE));

        for position in 0..PER_LINE {
            match chunk.get(position) {
                Some(byte) => out.push_str(&format!("{byte:02x} ")),
                None => out.push_str("   "),
            }
            // The traditional gap at the halfway point, which is what makes a dump
            // scannable by eye.
            if position == PER_LINE / 2 - 1 {
                out.push(' ');
            }
        }

        out.push_str(" |");
        for byte in chunk {
            out.push(if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    out
}

/// Renders a raw header block for display, without interpreting it.
///
/// Stored header blocks are bytes, and a header value is allowed to contain anything
/// except CR and LF. Decoded lossily so a non-UTF-8 value cannot hide the headers
/// around it — the exact bytes remain available through the body preview path.
pub fn header_block(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_body_is_reported_as_empty_rather_than_as_empty_text() {
        // The UI shows "no body" instead of a blank pane that looks like a bug.
        let preview = BodyPreview::of(b"");
        assert_eq!(preview.rendering, Rendering::Empty);
        assert_eq!(preview.total_bytes, 0);
        assert!(!preview.truncated);
    }

    #[test]
    fn utf8_text_is_shown_as_text_byte_for_byte() {
        let preview = BodyPreview::of("hello — world".as_bytes());
        assert_eq!(preview.rendering, Rendering::Text);
        assert_eq!(preview.content, "hello — world");
        assert!(!preview.truncated);
    }

    #[test]
    fn a_body_with_a_nul_byte_is_treated_as_binary() {
        // PNG, gzip, anything compiled. Rendering these as lossy text hides whatever
        // was worth seeing behind a screen of replacement characters.
        let preview = BodyPreview::of(&[0x89, b'P', b'N', b'G', 0x00, 0x1a]);
        assert_eq!(preview.rendering, Rendering::Binary);
        assert!(
            preview.content.contains("89 50 4e 47"),
            "{}",
            preview.content
        );
    }

    #[test]
    fn invalid_utf8_is_hex_not_lossy_text() {
        // The important one. Lossy decoding puts characters on screen that were never
        // on the wire, which for a security tool is a correctness bug, not a display
        // choice.
        let preview = BodyPreview::of(&[0xff, 0xfe, 0x41]);
        assert_eq!(preview.rendering, Rendering::Binary);
        assert!(preview.content.contains("ff fe 41"), "{}", preview.content);
        assert!(
            !preview.content.contains('\u{fffd}'),
            "no replacement characters may appear"
        );
    }

    #[test]
    fn a_large_body_is_truncated_and_says_so() {
        let body = vec![b'a'; PREVIEW_LIMIT + 5_000];
        let preview = BodyPreview::of(&body);

        assert_eq!(preview.rendering, Rendering::Text);
        assert_eq!(preview.content.len(), PREVIEW_LIMIT);
        assert_eq!(
            preview.total_bytes,
            PREVIEW_LIMIT + 5_000,
            "the real size is reported even though the content is not"
        );
        assert!(preview.truncated);
    }

    #[test]
    fn a_body_exactly_at_the_limit_is_not_marked_truncated() {
        let preview = BodyPreview::of(&vec![b'a'; PREVIEW_LIMIT]);
        assert!(!preview.truncated);
        assert_eq!(preview.content.len(), PREVIEW_LIMIT);
    }

    #[test]
    fn truncating_mid_character_does_not_turn_text_into_binary() {
        // A multi-byte character straddling the cut is not the body being binary, and
        // declaring a perfectly ordinary UTF-8 page unreadable would be a bad bug.
        let mut body = "é".repeat(PREVIEW_LIMIT).into_bytes();
        body.truncate(PREVIEW_LIMIT * 2);

        let preview = BodyPreview::of(&body);
        assert_eq!(
            preview.rendering,
            Rendering::Text,
            "{:?}",
            preview.rendering
        );
        assert!(preview.truncated);
        assert!(
            !preview.content.contains('\u{fffd}'),
            "the partial character is dropped, not mangled"
        );
    }

    #[test]
    fn a_hex_dump_carries_offsets_and_an_ascii_column() {
        let dump = hex_dump(b"Hello, world!\x00\x01\x02 and more");
        let first = dump.lines().next().unwrap();

        assert!(first.starts_with("00000000  "), "{first}");
        assert!(first.contains("48 65 6c 6c 6f"), "{first}");
        assert!(first.contains("|Hello, world!"), "{first}");
        // Unprintables become dots rather than moving the columns.
        assert!(first.contains("..."), "{first}");
        assert!(dump.lines().nth(1).unwrap().starts_with("00000010  "));
    }

    #[test]
    fn a_short_final_line_keeps_its_columns_aligned() {
        // Otherwise the ASCII column of the last line lands somewhere else and the
        // dump stops being scannable.
        let dump = hex_dump(b"ab");
        let line = dump.lines().next().unwrap();
        assert!(line.contains("|ab|"), "{line}");
        assert_eq!(
            line.find('|'),
            hex_dump(b"0123456789abcdef")
                .lines()
                .next()
                .unwrap()
                .find('|')
        );
    }

    #[test]
    fn the_sniff_window_bounds_the_work_on_a_huge_body() {
        // A NUL far past the sniff window does not make a body binary; the point is
        // that the check stays cheap enough to run on every row.
        let mut body = vec![b'a'; SNIFF_WINDOW * 4];
        body.push(0);
        assert!(!looks_binary(&body));
    }

    #[test]
    fn a_header_block_survives_display_unchanged() {
        let raw = b"Host: example.com\r\nx-Odd-Casing: kept\r\n";
        let rendered = header_block(raw);
        assert!(rendered.contains("x-Odd-Casing: kept"), "{rendered}");
    }

    #[test]
    fn a_preview_serializes_with_the_fields_the_ui_reads() {
        let json = serde_json::to_value(BodyPreview::of(b"body")).unwrap();
        for key in ["rendering", "content", "total_bytes", "truncated"] {
            assert!(json.get(key).is_some(), "{key} missing from {json}");
        }
        assert_eq!(json["rendering"], "text");
    }
}
