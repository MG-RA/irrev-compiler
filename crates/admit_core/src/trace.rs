use crate::witness::Fact;

#[derive(Debug, Default)]
pub struct Trace {
    facts: Vec<Fact>,
}

impl Trace {
    pub fn new() -> Self {
        Self { facts: Vec::new() }
    }

    pub fn record(&mut self, fact: Fact) {
        self.facts.push(fact);
    }

    pub fn into_facts(self) -> Vec<Fact> {
        self.facts
    }
}
