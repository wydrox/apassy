//! Text rules shared by the Mac app, the relay crate, and the iPhone core: which
//! characters a name that the owner reads to decide must not carry. It needs no
//! feature, so every crate of the workspace can use it.

/// True for a character that must not be in a name that the owner reads to decide (the
/// client name of a connect request on the connect page, in the Touch ID prompt, and on
/// the iPhone card; the name of a remote agent): a control character (category Cc), a
/// format character (category Cf of Unicode 17: the soft hyphen, the Arabic and Syriac
/// marks, the bidirectional controls, the zero-width characters, the invisible
/// operators, the interlinear annotation, and the others), or any code point of the tag
/// block U+E0000–U+E007F. Such a character can hide, reorder, or smuggle text that the
/// owner does not see.
pub fn is_hidden_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Unicode 17: ucd/extracted/DerivedGeneralCategory.txt, category Cf.
            '\u{00AD}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                // U+2065 is unassigned and default ignorable: hidden too.
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                // The whole tag block, with its unassigned code points.
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// `text` without the characters of [`is_hidden_char`].
pub fn strip_hidden(text: &str) -> String {
    text.chars().filter(|&c| !is_hidden_char(c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_characters_are_controls_format_characters_and_the_tag_block() {
        let hidden = concat!(
            "\u{0}\n\t\u{7F}\u{9F}\u{AD}\u{600}\u{605}\u{61C}\u{6DD}\u{70F}\u{890}\u{891}",
            "\u{8E2}\u{180E}\u{200B}\u{200D}\u{200F}\u{202A}\u{202E}\u{2060}\u{2064}\u{2065}",
            "\u{2066}\u{2069}\u{206A}\u{206F}\u{FEFF}\u{FFF9}\u{FFFB}\u{110BD}\u{110CD}",
            "\u{13430}\u{1343F}\u{1BCA0}\u{1BCA3}\u{1D173}\u{1D17A}",
            "\u{E0000}\u{E0001}\u{E0002}\u{E001F}\u{E0020}\u{E0041}\u{E007F}",
        );
        for c in hidden.chars() {
            assert!(is_hidden_char(c), "U+{:04X}", u32::from(c));
        }
        let shown = "aZ7 -\u{E9}\u{2013}\u{3000}\u{FE0F}\u{FFFC}\u{E0080}\u{1F600}";
        for c in shown.chars() {
            assert!(!is_hidden_char(c), "U+{:04X}", u32::from(c));
        }
        assert_eq!(
            strip_hidden("Gr\u{202E}ok\u{E0041}\u{E0001}\u{061C} B\u{180E}ot\u{206A}\u{FFF9}\u{7}"),
            "Grok Bot"
        );
        assert_eq!(strip_hidden("\u{200B}\u{E007F}"), "");
    }
}
