use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Number(pub f64);

impl Number {
    pub fn new(value: f64) -> Self {
        Self(value)
    }
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for Number {}

impl Hash for Number {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.0.to_bits());
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Token {
    Ident(String),
    Number(Number),
    Str(String),
    KwModule,
    KwScope,
    KwLens,
    KwScopeChange,
    KwAllowScopeChange,
    KwScopeChangeRule,
    KwMetaChange,
    KwFrom,
    KwTo,
    KwPayload,
    KwRoute,
    KwHash,
    KwDepends,
    KwDifference,
    KwTransform,
    KwBucket,
    KwConstraint,
    KwPersist,
    KwUnder,
    KwDenyErase,
    KwAllowErase,
    KwErasureRule,
    KwCost,
    KwCommit,
    KwInadmissibleIf,
    KwTag,
    KwQuery,
    KwAdmissible,
    KwWitness,
    KwDelta,
    KwInterpretationDelta,
    KwLint,
    KwFailOn,
    KwUnit,
    KwAllow,
    KwAnd,
    KwOr,
    KwNot,
    KwEraseAllowed,
    KwDisplacedTotal,
    KwHasCommit,
    KwCommitEquals,
    KwCommitCmp,
    KwObsidianVaultRule,
    KwVaultRule,
    True,
    False,
    LBracket,
    RBracket,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    Semi,
    At,
    Arrow,
    Eq,
    CmpEq,
    CmpNeq,
    CmpGt,
    CmpGte,
    CmpLt,
    CmpLte,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::Ident(s) => write!(f, "identifier `{}`", s),
            Token::Number(n) => write!(f, "number `{}`", n),
            Token::Str(s) => write!(f, "string `{}`", s),
            Token::KwModule => write!(f, "'module'"),
            Token::KwScope => write!(f, "'scope'"),
            Token::KwLens => write!(f, "'lens'"),
            Token::KwScopeChange => write!(f, "'scope_change'"),
            Token::KwAllowScopeChange => write!(f, "'allow_scope_change'"),
            Token::KwScopeChangeRule => write!(f, "'scope_change_rule'"),
            Token::KwMetaChange => write!(f, "'meta_change'"),
            Token::KwFrom => write!(f, "'from'"),
            Token::KwTo => write!(f, "'to'"),
            Token::KwPayload => write!(f, "'payload'"),
            Token::KwRoute => write!(f, "'route'"),
            Token::KwHash => write!(f, "'hash'"),
            Token::KwDepends => write!(f, "'depends'"),
            Token::KwDifference => write!(f, "'difference'"),
            Token::KwTransform => write!(f, "'transform'"),
            Token::KwBucket => write!(f, "'bucket'"),
            Token::KwConstraint => write!(f, "'constraint'"),
            Token::KwPersist => write!(f, "'persist'"),
            Token::KwUnder => write!(f, "'under'"),
            Token::KwDenyErase => write!(f, "'deny_erase'"),
            Token::KwAllowErase => write!(f, "'allow_erase'"),
            Token::KwErasureRule => write!(f, "'erasure_rule'"),
            Token::KwCost => write!(f, "'cost'"),
            Token::KwCommit => write!(f, "'commit'"),
            Token::KwInadmissibleIf => write!(f, "'inadmissible_if'"),
            Token::KwTag => write!(f, "'tag'"),
            Token::KwQuery => write!(f, "'query'"),
            Token::KwAdmissible => write!(f, "'admissible'"),
            Token::KwWitness => write!(f, "'witness'"),
            Token::KwDelta => write!(f, "'delta'"),
            Token::KwInterpretationDelta => write!(f, "'interpretation_delta'"),
            Token::KwLint => write!(f, "'lint'"),
            Token::KwFailOn => write!(f, "'fail_on'"),
            Token::KwUnit => write!(f, "'unit'"),
            Token::KwAllow => write!(f, "'allow'"),
            Token::KwAnd => write!(f, "'and'"),
            Token::KwOr => write!(f, "'or'"),
            Token::KwNot => write!(f, "'not'"),
            Token::KwEraseAllowed => write!(f, "'erase_allowed'"),
            Token::KwDisplacedTotal => write!(f, "'displaced_total'"),
            Token::KwHasCommit => write!(f, "'has_commit'"),
            Token::KwCommitEquals => write!(f, "'commit_equals'"),
            Token::KwCommitCmp => write!(f, "'commit_cmp'"),
            Token::KwObsidianVaultRule => write!(f, "'obsidian_vault_rule'"),
            Token::KwVaultRule => write!(f, "'vault_rule'"),
            Token::True => write!(f, "'true'"),
            Token::False => write!(f, "'false'"),
            Token::LBracket => write!(f, "'['"),
            Token::RBracket => write!(f, "']'"),
            Token::LParen => write!(f, "'('"),
            Token::RParen => write!(f, "')'"),
            Token::LBrace => write!(f, "'{{'"),
            Token::RBrace => write!(f, "'}}'"),
            Token::Comma => write!(f, "','"),
            Token::Semi => write!(f, "';'"),
            Token::At => write!(f, "'@'"),
            Token::Arrow => write!(f, "'->'"),
            Token::Eq => write!(f, "'='"),
            Token::CmpEq => write!(f, "'=='"),
            Token::CmpNeq => write!(f, "'!='"),
            Token::CmpGt => write!(f, "'>'"),
            Token::CmpGte => write!(f, "'>='"),
            Token::CmpLt => write!(f, "'<'"),
            Token::CmpLte => write!(f, "'<='"),
        }
    }
}
