#[derive(Debug, Clone)]
pub struct OpenVMTrace {
    /// List of chip rows in the trace.
    pub chip_rows: Vec<ChipRow>,
    /// List of interactions in the trace.
    pub interactions: Vec<Interaction>,
    /// List of instructions in the trace.
    pub instructions: Vec<Insn>,

    /// Below are indexed views (by table, by chip row id, by anchor, op_spans).
    /// Map of interactions by table id.
    pub interactions_by_table: HashMap<String, Vec<&Interaction>>,
    /// Map of chip rows by id.
    pub chip_rows_by_id: HashMap<String, &ChipRow>,
    /// Map of chip rows by kind.
    pub chip_rows_by_kind: HashMap<ChipRowKind, Vec<ChipRow>>,
    /// Map of interactions by anchor row id.
    pub interactions_by_anchor_row_id: HashMap<String, Vec<Interaction>>,
}

impl ZKVMTrace {
    /// Build a trace from `micro_ops`, optional extra `chip_rows`, and optional `op_spans`.
    pub fn new(
        micro_ops: Vec<MicroOp>,
        chip_rows: Option<Vec<ChipRow>>,
        op_spans: Option<Vec<Vec<usize>>>,
    ) -> Result<Self, String> {
        let len = micro_ops.len();
        if let Some(ref spans) = op_spans {
            for (op_idx, span) in spans.iter().enumerate() {
                if span.is_empty() {
                    return Err(format!("op_spans[{}] is empty", op_idx));
                }
                for &i in span {
                    if i >= len {
                        return Err(format!(
                            "op_spans[{}] contains out-of-range index {} (len(micro_ops)={})",
                            op_idx, i, len
                        ));
                    }
                }
            }
        }

        let chip_rows: Vec<ChipRow> = micro_ops
            .iter()
            .filter_map(|u| match u {
                MicroOp::ChipRow(r) => Some(r.clone()),
                _ => None,
            })
            .chain(chip_rows.into_iter().flatten())
            .collect();

        let interactions: Vec<Interaction> = micro_ops
            .iter()
            .filter_map(|u| match u {
                MicroOp::Interaction(i) => Some(i.clone()),
                _ => None,
            })
            .collect();

        let mut interactions_by_table: HashMap<String, Vec<Interaction>> = HashMap::new();
        for uop in &interactions {
            interactions_by_table.entry(uop.base().table_id.clone()).or_default().push(uop.clone());
        }

        let chip_rows_by_id: HashMap<String, ChipRow> =
            chip_rows.iter().map(|r| (r.row_id.clone(), r.clone())).collect();

        let mut chip_rows_by_kind: HashMap<ChipRowKind, Vec<ChipRow>> = HashMap::new();
        for row in &chip_rows {
            chip_rows_by_kind.entry(row.kind.clone()).or_default().push(row.clone());
        }

        let mut interactions_by_anchor_row_id: HashMap<String, Vec<Interaction>> = HashMap::new();
        for uop in &interactions {
            if let Some(ref aid) = uop.base().anchor_row_id {
                interactions_by_anchor_row_id.entry(aid.clone()).or_default().push(uop.clone());
            }
        }

        Ok(Self {
            micro_ops,
            op_spans,
            chip_rows,
            interactions,
            interactions_by_table,
            chip_rows_by_id,
            chip_rows_by_kind,
            interactions_by_anchor_row_id,
        })
    }

    pub fn by_table_id(&self, table_id: &str) -> &[Interaction] {
        self.interactions_by_table.get(table_id).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn chip_row(&self, row_id: &str) -> Option<&ChipRow> {
        self.chip_rows_by_id.get(row_id)
    }

    pub fn chip_rows_of_kind(&self, kind: &ChipRowKind) -> &[ChipRow] {
        self.chip_rows_by_kind.get(kind).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn by_anchor_row_id(&self, row_id: &str) -> &[Interaction] {
        self.interactions_by_anchor_row_id.get(row_id).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn op_micro_ops(&self, op_idx: usize) -> Result<Vec<MicroOp>, String> {
        let spans = self
            .op_spans
            .as_ref()
            .ok_or_else(|| "Trace has no op_spans; op-level access is unavailable".to_string())?;
        let span = spans.get(op_idx).ok_or_else(|| format!("op_spans has no index {}", op_idx))?;
        Ok(span.iter().filter_map(|&i| self.micro_ops.get(i).cloned()).collect())
    }

    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.micro_ops.is_empty() {
            errors.push("Trace is empty".to_string());
            return errors;
        }
        if self.chip_rows_by_id.len() != self.chip_rows.len() {
            errors.push("Trace has duplicate ChipRow.row_id values".to_string());
        }
        for uop in &self.interactions {
            if let Some(ref aid) = uop.base().anchor_row_id {
                if !self.chip_rows_by_id.contains_key(aid) {
                    errors.push(format!("Interaction references missing anchor_row_id={:?}", aid));
                }
            }
        }
        errors
    }

    /// OpenVM-specific: construct an op-level `ZKVMTrace` from OpenVM-emitted micro-ops.
    ///
    /// This relies on the OpenVM emitter providing explicit `step` fields on emitted micro-ops
    /// (chip rows and interactions). Micro-ops without an explicit step are excluded from spans.
    pub fn from_openvm_micro_ops(micro_ops: Vec<MicroOp>) -> Result<Self, String> {
        fn step_for_micro_op(uop: &MicroOp) -> Option<u64> {
            match uop {
                MicroOp::ChipRow(r) => r.step,
                MicroOp::Interaction(i) => i.base().step,
            }
        }

        let mut by_step: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for (idx, uop) in micro_ops.iter().enumerate() {
            let Some(step) = step_for_micro_op(uop) else {
                continue;
            };
            by_step.entry(step).or_default().push(idx);
        }
        let op_spans: Vec<Vec<usize>> = by_step.into_values().collect();

        let trace = ZKVMTrace::new(micro_ops, None, Some(op_spans))?;
        let errors = trace.validate();
        if !errors.is_empty() {
            return Err(format!("ZKVMTrace::validate failed: {}", errors.join("; ")));
        }
        Ok(trace)
    }
}