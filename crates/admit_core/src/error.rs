use std::fmt;

#[derive(Debug)]
pub struct EvalError(pub String);

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EvalError: {}", self.0)
    }
}

impl std::error::Error for EvalError {}
