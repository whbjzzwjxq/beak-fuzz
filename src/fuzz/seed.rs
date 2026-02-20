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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_from_jsonl() {
        const JSONL: &str = include_str!("../../storage/fuzzing_seeds/initial.jsonl");
        let mut count = 0usize;
        for line in JSONL.lines().filter(|line| !line.trim().is_empty()) {
            let seed: FuzzingSeed =
                serde_json::from_str(line).expect("failed to parse seed json");
            assert!(!seed.instructions.is_empty());
            count += 1;
        }
        assert_eq!(count, 2172);
    }
}
