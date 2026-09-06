use serde::{Deserialize, Serialize};
use serde_json::Map;

pub type Metadata = Map<String, serde_json::Value>;

#[derive(Serialize, Deserialize)]
pub struct FuzzingSeed {
    pub instructions: Vec<u32>,
    pub metadata: Metadata,
}

impl FuzzingSeed {
    pub fn new(instructions: Vec<u32>, metadata: Metadata) -> Self {
        Self { instructions, metadata }
    }

    /// Parse either Beak's canonical seed shape or a replay-manifest row.
    ///
    /// Replay manifests carry the program as whitespace/comma-separated
    /// hexadecimal words in `seed_hex`.  Keeping this normalization here makes
    /// every ordinary fuzz loop consume the same two documented seed shapes.
    pub fn from_jsonl_str(line: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|err| format!("invalid seed JSON: {err}"))?;
        let object =
            value.as_object().ok_or_else(|| "seed row must be a JSON object".to_string())?;

        let has_instructions = object.contains_key("instructions");
        let has_seed_hex = object.contains_key("seed_hex");
        match (has_instructions, has_seed_hex) {
            (true, true) => {
                Err("seed row is ambiguous: provide either instructions or seed_hex, not both"
                    .to_string())
            }
            (true, false) => serde_json::from_value(value)
                .map_err(|err| format!("invalid canonical seed row: {err}")),
            (false, true) => {
                let encoded = object
                    .get("seed_hex")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "seed_hex must be a string".to_string())?;
                let instructions = parse_hex_words(encoded)?;
                let mut metadata = object.clone();
                metadata.remove("seed_hex");
                Ok(Self::new(instructions, metadata))
            }
            (false, false) => Err("seed row must contain instructions or seed_hex".to_string()),
        }
    }
}

fn parse_hex_words(encoded: &str) -> Result<Vec<u32>, String> {
    let mut words = Vec::new();
    for token in encoded.split(|c: char| c.is_whitespace() || c == ',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let digits = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")).unwrap_or(token);
        if digits.is_empty() || digits.len() > 8 {
            return Err(format!("invalid hexadecimal instruction word: {token}"));
        }
        let word = u32::from_str_radix(digits, 16)
            .map_err(|_| format!("invalid hexadecimal instruction word: {token}"))?;
        words.push(word);
    }
    if words.is_empty() {
        return Err("seed_hex must contain at least one instruction word".to_string());
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_from_jsonl() {
        const JSONL: &str = include_str!("../../../../storage/fuzzing_seeds/initial.jsonl");
        let mut count = 0usize;
        for line in JSONL.lines().filter(|line| !line.trim().is_empty()) {
            let seed: FuzzingSeed = serde_json::from_str(line).expect("failed to parse seed json");
            assert!(!seed.instructions.is_empty());
            count += 1;
        }
        assert_eq!(count, 2184);
    }

    #[test]
    fn parses_canonical_and_replay_seed_rows() {
        let canonical = FuzzingSeed::from_jsonl_str(
            r#"{"instructions":[19,1048723],"metadata":{"source":"unit"}}"#,
        )
        .unwrap();
        assert_eq!(canonical.instructions, vec![19, 1_048_723]);
        assert_eq!(canonical.metadata["source"], "unit");

        let replay = FuzzingSeed::from_jsonl_str(
            r#"{"seed_hex":"00000013, 0x00100093","frontend":"bin","args":[]}"#,
        )
        .unwrap();
        assert_eq!(replay.instructions, vec![0x0000_0013, 0x0010_0093]);
        assert_eq!(replay.metadata["frontend"], "bin");
        assert!(replay.metadata.get("seed_hex").is_none());
    }

    #[test]
    fn replay_seed_rows_fail_closed() {
        for row in [
            r#"{"seed_hex":""}"#,
            r#"{"seed_hex":"not-hex"}"#,
            r#"{"seed_hex":"000000001"}"#,
            r#"{"instructions":[19],"seed_hex":"00000013","metadata":{}}"#,
            r#"{"frontend":"bin"}"#,
        ] {
            assert!(FuzzingSeed::from_jsonl_str(row).is_err(), "row={row}");
        }
    }
}
