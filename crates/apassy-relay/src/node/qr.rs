//! A QR code in the terminal for `apassy pair` (`qrcode` without features).
//!
//! Two modules per character cell, with the half blocks `▀`, `▄`, and `█`. The light
//! modules and a quiet zone of two modules are drawn, the dark modules are left blank:
//! on the usual dark terminal this is a dark-on-light code that a phone camera reads.
//! The link is always printed as text too.

use qrcode::{Color, EcLevel, QrCode};

/// The quiet zone around the code, in modules.
const QUIET: usize = 2;

/// The QR code of `text` as lines of half blocks, each ending in `\n`; `None` when the
/// text does not fit in a QR code.
pub fn render(text: &str) -> Option<String> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    let size = width + 2 * QUIET;
    // Light outside the code (the quiet zone).
    let light = |x: usize, y: usize| -> bool {
        if x < QUIET || y < QUIET || x >= width + QUIET || y >= width + QUIET {
            return true;
        }
        colors[(y - QUIET) * width + (x - QUIET)] == Color::Light
    };
    let mut out = String::new();
    for y in (0..size).step_by(2) {
        for x in 0..size {
            let top = light(x, y);
            let bottom = y + 1 >= size || light(x, y + 1);
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_makes_a_square_of_half_blocks() {
        let link = "https://100.64.0.7:8444/pair#apassy_tcd_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]&name=build-box";
        let text = render(link).expect("a code");
        let lines: Vec<&str> = text.lines().collect();
        let width = QrCode::with_error_correction_level(link.as_bytes(), EcLevel::M)
            .unwrap()
            .width();
        let size = width + 2 * QUIET;
        assert_eq!(lines.len(), size.div_ceil(2));
        for line in &lines {
            assert_eq!(line.chars().count(), size);
            assert!(line.chars().all(|ch| matches!(ch, '█' | '▀' | '▄' | ' ')));
        }
        // The quiet zone: the first line is light from end to end.
        assert!(lines[0].chars().all(|ch| ch == '█'));
    }

    #[test]
    fn text_that_does_not_fit_has_no_code() {
        assert!(render(&"x".repeat(5000)).is_none());
    }
}
