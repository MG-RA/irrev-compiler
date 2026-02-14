use chumsky::prelude::*;

use crate::tokens::{Number, Token};

pub(crate) fn lexer(
) -> impl Parser<char, Vec<(Token, std::ops::Range<usize>)>, Error = Simple<char>> {
    let number = text::int(10)
        .then(just('.').then(text::digits(10)).or_not())
        .try_map(|(int_part, frac), span| {
            let mut s = int_part;
            if let Some((dot, frac)) = frac {
                s.push(dot);
                s.push_str(&frac);
            }
            s.parse::<f64>()
                .map_err(|_| Simple::custom(span, "invalid number literal"))
        })
        .map(|value| Token::Number(Number::new(value)));

    let string = just('"')
        .ignore_then(filter(|c| *c != '"').repeated().collect::<String>())
        .then_ignore(just('"'))
        .map(Token::Str);

    let symbol =
        filter(|c: &char| c.is_ascii_alphanumeric() || matches!(*c, '_' | ':' | '@' | '-'))
            .repeated()
            .at_least(1)
            .collect::<String>();
    let ident = symbol.clone().map(Token::Ident);

    let make_keyword = |word: &'static str, token: Token| {
        symbol.clone().try_map(move |raw: String, span| {
            if raw == word {
                Ok(token.clone())
            } else {
                Err(Simple::expected_input_found(span, None, None))
            }
        })
    };
    let keyword = choice::<_, Simple<char>>(vec![
        make_keyword("module", Token::KwModule).boxed(),
        make_keyword("scope", Token::KwScope).boxed(),
        make_keyword("lens", Token::KwLens).boxed(),
        make_keyword("scope_change", Token::KwScopeChange).boxed(),
        make_keyword("allow_scope_change", Token::KwAllowScopeChange).boxed(),
        make_keyword("scope_change_rule", Token::KwScopeChangeRule).boxed(),
        make_keyword("meta_change", Token::KwMetaChange).boxed(),
        make_keyword("from", Token::KwFrom).boxed(),
        make_keyword("to", Token::KwTo).boxed(),
        make_keyword("payload", Token::KwPayload).boxed(),
        make_keyword("route", Token::KwRoute).boxed(),
        make_keyword("hash", Token::KwHash).boxed(),
        make_keyword("depends", Token::KwDepends).boxed(),
        make_keyword("difference", Token::KwDifference).boxed(),
        make_keyword("transform", Token::KwTransform).boxed(),
        make_keyword("bucket", Token::KwBucket).boxed(),
        make_keyword("constraint", Token::KwConstraint).boxed(),
        make_keyword("persist", Token::KwPersist).boxed(),
        make_keyword("under", Token::KwUnder).boxed(),
        make_keyword("deny_erase", Token::KwDenyErase).boxed(),
        make_keyword("allow_erase", Token::KwAllowErase).boxed(),
        make_keyword("erasure_rule", Token::KwErasureRule).boxed(),
        make_keyword("cost", Token::KwCost).boxed(),
        make_keyword("commit", Token::KwCommit).boxed(),
        make_keyword("inadmissible_if", Token::KwInadmissibleIf).boxed(),
        make_keyword("tag", Token::KwTag).boxed(),
        make_keyword("query", Token::KwQuery).boxed(),
        make_keyword("admissible", Token::KwAdmissible).boxed(),
        make_keyword("witness", Token::KwWitness).boxed(),
        make_keyword("delta", Token::KwDelta).boxed(),
        make_keyword("interpretation_delta", Token::KwInterpretationDelta).boxed(),
        make_keyword("lint", Token::KwLint).boxed(),
        make_keyword("fail_on", Token::KwFailOn).boxed(),
        make_keyword("unit", Token::KwUnit).boxed(),
        make_keyword("allow", Token::KwAllow).boxed(),
        make_keyword("and", Token::KwAnd).boxed(),
        make_keyword("or", Token::KwOr).boxed(),
        make_keyword("not", Token::KwNot).boxed(),
        make_keyword("erase_allowed", Token::KwEraseAllowed).boxed(),
        make_keyword("displaced_total", Token::KwDisplacedTotal).boxed(),
        make_keyword("has_commit", Token::KwHasCommit).boxed(),
        make_keyword("commit_equals", Token::KwCommitEquals).boxed(),
        make_keyword("commit_cmp", Token::KwCommitCmp).boxed(),
        make_keyword("obsidian_vault_rule", Token::KwObsidianVaultRule).boxed(),
        make_keyword("vault_rule", Token::KwVaultRule).boxed(),
        make_keyword("true", Token::True).boxed(),
        make_keyword("false", Token::False).boxed(),
    ]);

    let op = choice::<_, Simple<char>>(vec![
        just("->").to(Token::Arrow).boxed(),
        just("==").to(Token::CmpEq).boxed(),
        just("!=").to(Token::CmpNeq).boxed(),
        just(">=").to(Token::CmpGte).boxed(),
        just("<=").to(Token::CmpLte).boxed(),
        just(">").to(Token::CmpGt).boxed(),
        just("<").to(Token::CmpLt).boxed(),
        just("=").to(Token::Eq).boxed(),
        just("[").to(Token::LBracket).boxed(),
        just("]").to(Token::RBracket).boxed(),
        just("(").to(Token::LParen).boxed(),
        just(")").to(Token::RParen).boxed(),
        just("{").to(Token::LBrace).boxed(),
        just("}").to(Token::RBrace).boxed(),
        just(",").to(Token::Comma).boxed(),
        just(";").to(Token::Semi).boxed(),
        just("@").to(Token::At).boxed(),
    ]);

    let comment = just('#')
        .then(take_until(just('\n')))
        .ignored()
        .or(just('#').then(end()).ignored());

    choice::<_, Simple<char>>((keyword, number, string, op, ident))
        .map_with_span(|tok, span| (tok, span))
        .padded_by(comment.repeated())
        .padded()
        .repeated()
        .then_ignore(end())
}
