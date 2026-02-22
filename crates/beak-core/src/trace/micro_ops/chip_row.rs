// We decide to use different chip row for different zkvm.
// So we only define the trait here, and let each zkvm implement its own chip row.
// chip row means a single row in the table during the trace generation of a zkvm.
pub trait ChipRow: Send + Sync {}
