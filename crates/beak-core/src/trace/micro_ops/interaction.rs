// We decide to use different interaction for different zkvm.
// So we only define the trait here, and let each zkvm implement its own interaction.
// interaction means a single interaction in the trace generation of a zkvm.
pub trait Interaction: Send + Sync {
}
