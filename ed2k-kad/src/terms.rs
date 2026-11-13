// SPDX-License-Identifier: GPL-2.0-or-later
//! Search terms as an answering node reads them (`ParseSearchExpression`,
//! net/SearchExpression.cpp) and matches them against a stored keyword
//! entry (`CKeyEntry::SearchTermsMatch`, kademlia/Entry.cpp).
//!
//! Matching spends a budget of work units, shared by all the entries
//! one request is checked against, so a hostile query cannot make a node
//! do unbounded work: a term that cannot be paid for does not match.

use ed2k_codec::io::LenField;
use ed2k_codec::Reader;
use ed2k_server::search::INVALID_KEYWORD_CHARS;
use ed2k_types::tags::kad as tag;

/// `CKeyEntry::SEARCH_BUDGET`: work units for one request.
pub const SEARCH_BUDGET: u64 = 1_000_000_000;
/// Nesting limit of a term tree.
pub const MAX_DEPTH: u32 = 24;
/// Node limit of a term tree.
pub const MAX_NODES: u32 = 256;

const NODE_COST: u64 = 64;
const LOOKUP_COST: u64 = 128;
const NAME_COST: u64 = 64;
const LOWER_CHAR_COST: u64 = 20;
const CHAR_COST: u64 = 3;
const CANDIDATE_COST: u64 = 48;
const TAG_COST: u64 = 48;
const NOCASE_CHAR_COST: u64 = 50;

/// A comparison operator (`ED2K_SEARCH_OP_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    Equal,
    Greater,
    Less,
    GreaterEqual,
    LessEqual,
    NotEqual,
}

/// `SSearchTerm`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    And(Box<Term>, Box<Term>),
    Or(Box<Term>, Box<Term>),
    /// Left and not right.
    Not(Box<Term>, Box<Term>),
    /// Words that must all be in the name (lower-cased).
    Words(Vec<String>),
    /// A string tag equal to `value` (lower-cased), ignoring case.
    Meta {
        name: Vec<u8>,
        value: String,
    },
    /// An integer tag compared with `value`.
    Number {
        op: Cmp,
        name: Vec<u8>,
        value: u64,
    },
}

/// `ParseSearchExpression`: `None` for anything malformed, too deep or too big.
pub fn parse(data: &[u8]) -> Option<Term> {
    let mut r = Reader::new(data);
    let mut nodes = 0;
    node(&mut r, 0, &mut nodes)
}

fn node(r: &mut Reader<'_>, level: u32, nodes: &mut u32) -> Option<Term> {
    if level >= MAX_DEPTH {
        return None;
    }
    *nodes += 1;
    if *nodes > MAX_NODES {
        return None;
    }
    match r.u8().ok()? {
        0x00 => {
            let op = r.u8().ok()?;
            if op > 2 {
                return None;
            }
            let left = Box::new(node(r, level + 1, nodes)?);
            let right = Box::new(node(r, level + 1, nodes)?);
            Some(match op {
                0 => Term::And(left, right),
                1 => Term::Or(left, right),
                _ => Term::Not(left, right),
            })
        }
        0x01 => {
            let s = r.string(true, LenField::U16, false).ok()?.to_lowercase();
            let words = s
                .split(|c| INVALID_KEYWORD_CHARS.contains(c))
                .filter(|w| !w.is_empty())
                .map(str::to_owned)
                .collect();
            Some(Term::Words(words))
        }
        0x02 => {
            let value = r.string(true, LenField::U16, false).ok()?;
            if value.chars().count() > 256 {
                return None;
            }
            let n = r.u16().ok()? as usize;
            let name = r.bytes(n).ok()?.to_vec();
            Some(Term::Meta {
                name,
                value: value.to_lowercase(),
            })
        }
        op @ (0x03 | 0x08) => {
            let value = if op == 0x03 {
                r.u32().ok()? as u64
            } else {
                r.u64().ok()?
            };
            let op = match r.u8().ok()? {
                0 => Cmp::Equal,
                1 => Cmp::Greater,
                2 => Cmp::Less,
                3 => Cmp::GreaterEqual,
                4 => Cmp::LessEqual,
                5 => Cmp::NotEqual,
                _ => return None,
            };
            let n = r.u16().ok()? as usize;
            let name = r.bytes(n).ok()?.to_vec();
            Some(Term::Number { op, name, value })
        }
        _ => None,
    }
}

/// What a term is matched against.
pub trait Matchable {
    /// The most popular file name.
    fn name(&self) -> &str;
    /// An integer tag (`TAG_FILESIZE` is always there, as the entry's size).
    fn int_tag(&self, name: &[u8]) -> Option<u64>;
    /// A string tag.
    fn str_tag(&self, name: &[u8]) -> Option<&str>;
    /// How many tags (for the cost).
    fn tag_count(&self) -> usize;
}

struct State<'a, M: Matchable + ?Sized> {
    budget: &'a mut u64,
    entry: &'a M,
    name: Option<Vec<char>>,
    extension: Option<Option<String>>,
    exhausted: bool,
}

impl<M: Matchable + ?Sized> State<'_, M> {
    fn spend(&mut self, cost: u64) -> bool {
        if self.exhausted || cost > *self.budget {
            *self.budget = 0;
            self.exhausted = true;
            return false;
        }
        *self.budget -= cost;
        true
    }

    fn name_lower(&mut self) -> Option<Vec<char>> {
        if self.name.is_none() {
            let n: Vec<char> = self.entry.name().to_lowercase().chars().collect();
            let cost = NAME_COST + LOWER_CHAR_COST * n.len() as u64;
            self.name = Some(n);
            if !self.spend(cost) {
                return None;
            }
        }
        if self.exhausted {
            None
        } else {
            self.name.clone()
        }
    }

    fn extension(&mut self) -> Option<String> {
        if self.extension.is_none() {
            let name = self.name_lower()?;
            if !self.spend(LOOKUP_COST + CHAR_COST * name.len() as u64) {
                self.extension = Some(None);
                return None;
            }
            let ext = name
                .iter()
                .rposition(|&c| c == '.')
                .map(|p| name[p + 1..].iter().collect());
            self.extension = Some(ext);
        }
        if self.exhausted {
            None
        } else {
            self.extension.clone().flatten()
        }
    }

    fn equal_no_case(&mut self, a: &str, b: &str) -> bool {
        let n = a.chars().count().min(b.chars().count()) as u64;
        self.spend(LOOKUP_COST + NOCASE_CHAR_COST * n) && a.to_lowercase() == b.to_lowercase()
    }

    fn contains(&mut self, name: &[char], word: &str) -> bool {
        let word: Vec<char> = word.chars().collect();
        if !self.spend(LOOKUP_COST + CHAR_COST * name.len() as u64) {
            return false;
        }
        let Some(&first) = word.first() else {
            return true;
        };
        let mut pos = 0;
        while let Some(off) = name[pos..].iter().position(|&c| c == first) {
            let p = pos + off;
            if p + word.len() > name.len() {
                break;
            }
            if !self.spend(CANDIDATE_COST + CHAR_COST * word.len() as u64) {
                return false;
            }
            if name[p..p + word.len()] == word[..] {
                return true;
            }
            pos = p + 1;
        }
        false
    }

    fn matches(&mut self, t: &Term) -> bool {
        if !self.spend(NODE_COST) {
            return false;
        }
        match t {
            Term::And(l, r) => self.matches(l) && self.matches(r),
            Term::Or(l, r) => self.matches(l) || self.matches(r),
            Term::Not(l, r) => self.matches(l) && !self.matches(r),
            Term::Words(words) => {
                if words.is_empty() {
                    return false;
                }
                let Some(name) = self.name_lower() else {
                    return false;
                };
                words.iter().all(|w| self.contains(&name, w))
            }
            _ => {
                if !self.spend(TAG_COST * self.entry.tag_count() as u64) {
                    return false;
                }
                match t {
                    Term::Meta { name, value } => {
                        if name.as_slice() == tag::FILEFORMAT {
                            match self.extension() {
                                Some(ext) => self.equal_no_case(&ext, value),
                                None => false,
                            }
                        } else {
                            match self.entry.str_tag(name) {
                                Some(s) => {
                                    let s = s.to_owned();
                                    self.equal_no_case(&s, value)
                                }
                                None => false,
                            }
                        }
                    }
                    Term::Number { op, name, value } => match self.entry.int_tag(name) {
                        Some(v) => match op {
                            Cmp::Equal => v == *value,
                            Cmp::Greater => v > *value,
                            Cmp::Less => v < *value,
                            Cmp::GreaterEqual => v >= *value,
                            Cmp::LessEqual => v <= *value,
                            Cmp::NotEqual => v != *value,
                        },
                        None => false,
                    },
                    _ => false,
                }
            }
        }
    }
}

/// `SearchTermsMatch`: whether `entry` matches, spending from `budget`.
pub fn matches<M: Matchable + ?Sized>(term: &Term, entry: &M, budget: &mut u64) -> bool {
    let mut s = State {
        budget,
        entry,
        name: None,
        extension: None,
        exhausted: false,
    };
    s.matches(term) && !s.exhausted
}
