use crate::symbols::{ScopeId, SymbolNamespace, SymbolRef};

// Convention: boundary-loss accounting reuses the erasure machinery by modeling
// the loss surface as a synthetic difference with a stable name.
pub fn boundary_loss_diff_name(from: &ScopeId, to: &ScopeId) -> String {
    format!("boundary_loss:{}->{}", from.0, to.0)
}

pub fn boundary_loss_diff(from: &ScopeId, to: &ScopeId) -> SymbolRef {
    SymbolRef {
        ns: SymbolNamespace::Difference,
        name: boundary_loss_diff_name(from, to),
    }
}
