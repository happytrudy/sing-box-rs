use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

pub fn parse_extended_json<T: DeserializeOwned>(input: &str) -> Result<T> {
    let stripped = strip_json_comments(input)?;
    serde_json::from_str(&stripped).context("decode extended JSON")
}

pub fn strip_json_comments(input: &str) -> Result<String> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum State {
        Normal,
        String,
        Escape,
        LineComment,
        BlockComment,
    }

    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut state = State::Normal;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match state {
            State::Normal => match (byte, bytes.get(index + 1).copied()) {
                (b'"', _) => {
                    output.push(byte);
                    state = State::String;
                }
                (b'/', Some(b'/')) => {
                    output.extend_from_slice(b"  ");
                    index += 1;
                    state = State::LineComment;
                }
                (b'/', Some(b'*')) => {
                    output.extend_from_slice(b"  ");
                    index += 1;
                    state = State::BlockComment;
                }
                _ => output.push(byte),
            },
            State::String => {
                output.push(byte);
                match byte {
                    b'\\' => state = State::Escape,
                    b'"' => state = State::Normal,
                    _ => {}
                }
            }
            State::Escape => {
                output.push(byte);
                state = State::String;
            }
            State::LineComment => {
                if byte == b'\n' || byte == b'\r' {
                    output.push(byte);
                    state = State::Normal;
                } else {
                    output.push(b' ');
                }
            }
            State::BlockComment => {
                if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    output.extend_from_slice(b"  ");
                    index += 1;
                    state = State::Normal;
                } else if byte == b'\n' || byte == b'\r' {
                    output.push(byte);
                } else {
                    output.push(b' ');
                }
            }
        }
        index += 1;
    }
    anyhow::ensure!(state != State::BlockComment, "unterminated block comment");
    String::from_utf8(output).context("extended JSON is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn removes_comments_without_changing_strings() {
        let value: Value = parse_extended_json(
            r#"{
                // line comment
                "url": "https://example.com/a//b",
                /* block
                   comment */
                "value": 1
            }"#,
        )
        .unwrap();
        assert_eq!(value["url"], "https://example.com/a//b");
        assert_eq!(value["value"], 1);
    }
}
