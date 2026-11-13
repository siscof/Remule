// SPDX-License-Identifier: GPL-2.0-or-later
//! Keyword searches on a server: the query language (Scanner.l, Parser.y,
//! `ParsedSearchExpression`, SearchPacket.cpp), the request
//! (`WriteSearchPacket`, SearchPacketWriter.h) and the answer
//! (`CSearchList::ProcessSearchAnswer`, `CSearchFile`).
//!
//! The query language: words separated by spaces are ANDed; `AND`, `OR`
//! and `NOT` (upper case) combine expressions, `NOT` binding tightest and
//! `OR` loosest, all left-associative; parentheses group; `"..."` is one
//! word that may hold spaces and C escapes. `ed2k::<32 hex digits>` alone
//! searches for a file hash.
//!
//! The request is a prefix tree: `<0><op>` for AND (0), OR (1), NOT (2),
//! `<1><string>` for a word, `<2><string><1 u16><tag>` for a text tag,
//! `<3><u32><cmp><1 u16><tag>` (or `<8><u64>...`) for a numeric one.

use ed2k_codec::io::{LenField, StrEncoding};
use ed2k_codec::{Reader, Tag, Writer};
use ed2k_types::ed2k::SearchCompare;
use ed2k_types::tags::{FileTag, FileType};
use ed2k_types::Md4Hash;

/// What can be wrong with a query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    #[error("empty search expression")]
    Empty,
    #[error("unterminated string in search expression")]
    UnterminatedString,
    #[error("missing left operand for {0} on search expression")]
    MissingLeftOperand(&'static str),
    #[error("missing right operand for {0} on search expression")]
    MissingRightOperand(&'static str),
    #[error("missing closing parenthesis on search expression")]
    MissingClosingParenthesis,
    #[error("unexpected {0:?} in search expression")]
    Unexpected(String),
    /// More than 10 operators: there is room for 11 more (one per filter).
    #[error("search expression is too complex")]
    TooComplex,
    /// Kad needs a word of at least 3 bytes to look up.
    #[error("no keyword for a Kad search (a word of 3 or more letters)")]
    NoKeyword,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    And,
    Or,
    Not,
    Open,
    Close,
    Ed2kLink(String),
}

fn is_ed2k_link(w: &str) -> bool {
    w.len() == 6 + 32 && w.starts_with("ed2k::") && w[6..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Scanner.l: only spaces separate; a word is anything but space, `"`, `(` and `)`.
fn lex(input: &str) -> Result<Vec<Token>, QueryError> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' => {
                chars.next();
            }
            '(' => {
                chars.next();
                out.push(Token::Open);
            }
            ')' => {
                chars.next();
                out.push(Token::Close);
            }
            '"' => {
                chars.next();
                out.push(Token::Word(quoted(&mut chars)?));
            }
            _ => {
                let mut w = String::new();
                while let Some(&c) = chars.peek() {
                    if matches!(c, ' ' | '"' | '(' | ')') {
                        break;
                    }
                    w.push(c);
                    chars.next();
                }
                out.push(match w.as_str() {
                    "OR" => Token::Or,
                    "AND" => Token::And,
                    "NOT" => Token::Not,
                    _ if is_ed2k_link(&w) => Token::Ed2kLink(w),
                    _ => Token::Word(w),
                });
            }
        }
    }
    Ok(out)
}

/// The rest of a `"..."` word. (Scanner.l pushes back a stray character
/// after a three-digit `\x` escape; that is not reproduced.)
fn quoted(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<String, QueryError> {
    let mut s = String::new();
    loop {
        let c = match chars.next() {
            None | Some('\n') => return Err(QueryError::UnterminatedString),
            Some('"') => return Ok(s),
            Some(c) => c,
        };
        if c != '\\' {
            s.push(c);
            continue;
        }
        let Some(e) = chars.next() else {
            return Err(QueryError::UnterminatedString);
        };
        let v = match e {
            '\n' => continue,
            't' => '\t',
            'n' => '\n',
            'f' => '\x0C',
            'r' => '\r',
            'v' => '\x0B',
            'a' => '\x07',
            'b' => '\x08',
            '?' => '?',
            'x' => {
                let mut n = 0u32;
                let mut digits = 0;
                while digits < 3 {
                    match chars.peek().and_then(|c| c.to_digit(16)) {
                        Some(d) => {
                            n = n * 16 + d;
                            digits += 1;
                            chars.next();
                        }
                        None => break,
                    }
                }
                if digits == 0 {
                    'x'
                } else {
                    char::from(n as u8)
                }
            }
            // \\, \", \' and anything else: the character itself.
            other => other,
        };
        s.push(v);
    }
}

/// A parsed expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Word(String),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>, Box<Expr>),
}

/// The flat prefix form `CSearchExpr` keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    And,
    Or,
    Not,
    Word(String),
}

impl Expr {
    fn flatten(&self, out: &mut Vec<Term>) {
        let (op, l, r) = match self {
            Expr::Word(w) => return out.push(Term::Word(w.clone())),
            Expr::And(l, r) => (Term::And, l, r),
            Expr::Or(l, r) => (Term::Or, l, r),
            Expr::Not(l, r) => (Term::Not, l, r),
        };
        out.push(op);
        l.flatten(out);
        r.flatten(out);
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

fn op_info(t: &Token) -> Option<(u8, &'static str)> {
    match t {
        Token::Or => Some((1, "OR")),
        Token::And => Some((2, "AND")),
        Token::Not => Some((3, "NOT")),
        _ => None,
    }
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn expr(&mut self, min_prec: u8) -> Result<Expr, QueryError> {
        let mut lhs = self.primary()?;
        while let Some((prec, name)) = self.peek().and_then(op_info) {
            if prec < min_prec {
                break;
            }
            let op = self.tokens[self.pos].clone();
            self.pos += 1;
            if self.peek().is_none() || self.peek() == Some(&Token::Close) {
                return Err(QueryError::MissingRightOperand(name));
            }
            let rhs = self.expr(prec + 1)?;
            lhs = match op {
                Token::And => Expr::And(lhs.into(), rhs.into()),
                Token::Or => Expr::Or(lhs.into(), rhs.into()),
                _ => Expr::Not(lhs.into(), rhs.into()),
            };
        }
        Ok(lhs)
    }

    fn primary(&mut self) -> Result<Expr, QueryError> {
        match self.peek().cloned() {
            Some(Token::Open) => {
                self.pos += 1;
                let e = self.expr(0)?;
                if self.peek() != Some(&Token::Close) {
                    return Err(QueryError::MissingClosingParenthesis);
                }
                self.pos += 1;
                Ok(e)
            }
            Some(Token::Word(w)) => {
                // and_strings: words side by side are ANDed, left to right.
                self.pos += 1;
                let mut e = Expr::Word(w);
                while let Some(Token::Word(w)) = self.peek().cloned() {
                    self.pos += 1;
                    e = Expr::And(e.into(), Expr::Word(w).into());
                }
                Ok(e)
            }
            Some(t) => match op_info(&t) {
                Some((_, name)) => Err(QueryError::MissingLeftOperand(name)),
                None => Err(QueryError::Unexpected(format!("{t:?}"))),
            },
            None => Err(QueryError::Empty),
        }
    }
}

/// Parse a query into the terms that go into the request (yyparse +
/// `ParsedSearchExpression` for an ed2k search): when only ANDs join the
/// words they become one string of words separated by spaces.
pub fn parse_query(query: &str) -> Result<Vec<Term>, QueryError> {
    Ok(parse_query_kad(query, "")?.0)
}

/// `CSearchManager::GetInvalidKeywordChars`
pub const INVALID_KEYWORD_CHARS: &str = r#" ()[]{}<>,._-!?:;\/""#;

/// `CSearchManager::GetWords`: the words of `s` that make Kad keywords,
/// lower-cased: split at [`INVALID_KEYWORD_CHARS`], at least 3 bytes of UTF-8.
pub fn kad_words(s: &str) -> Vec<String> {
    s.split(|c| INVALID_KEYWORD_CHARS.contains(c))
        .filter(|w| w.len() >= 3)
        .map(str::to_lowercase)
        .collect()
}

/// [`parse_query`] for a Kad search whose keyword is `keyword`
/// (`ParsedSearchExpression` with `s_strCurKadKeyword`): in a query of
/// ANDed words a longer word takes over as the keyword, and the keyword
/// itself is left out of the terms, the target already standing for it.
/// Returns the terms and the keyword, maybe replaced.
pub fn parse_query_kad(query: &str, keyword: &str) -> Result<(Vec<Term>, String), QueryError> {
    let mut keyword = keyword.to_owned();
    let tokens = lex(query)?;
    let terms = if let [Token::Ed2kLink(link)] = tokens.as_slice() {
        vec![Term::Word(link.clone())]
    } else {
        let mut p = Parser { tokens, pos: 0 };
        let e = p.expr(0)?;
        if let Some(t) = p.peek() {
            return Err(QueryError::Unexpected(format!("{t:?}")));
        }
        let mut terms = Vec::new();
        e.flatten(&mut terms);
        terms
    };
    let count = |want: &Term| terms.iter().filter(|t| *t == want).count();
    let (and, or, not) = (count(&Term::And), count(&Term::Or), count(&Term::Not));
    if and + or + not > 10 {
        return Err(QueryError::TooComplex);
    }
    let words = || {
        terms.iter().filter_map(|t| match t {
            Term::Word(w) => Some(w.as_str()),
            _ => None,
        })
    };
    if and > 0 && or == 0 && not == 0 {
        if !keyword.is_empty() {
            // The longest word (by characters) that could be a keyword.
            for w in words() {
                if w != keyword
                    && !w.contains(|c| INVALID_KEYWORD_CHARS.contains(c))
                    && !w.starts_with('"')
                    && w.chars().count() >= 3
                    && keyword.chars().count() < w.chars().count()
                {
                    keyword = w.to_owned();
                }
            }
        }
        let rest: Vec<&str> = words().filter(|w| *w != keyword).collect();
        return Ok((vec![Term::Word(rest.join(" "))], keyword));
    }
    // A lone word that is the keyword says nothing more.
    if terms.len() == 1 && terms[0] == Term::Word(keyword.clone()) {
        return Ok((Vec::new(), keyword));
    }
    Ok((terms, keyword))
}

/// `CSearchList::CSearchParams`, the parts a server search uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchParams {
    pub query: String,
    pub file_type: Option<FileType>,
    /// Bytes; 0 is no limit.
    pub min_size: u64,
    pub max_size: u64,
    /// Minimum number of sources.
    pub availability: u64,
    pub extension: String,
    /// kbit/s
    pub min_bitrate: u64,
    /// Seconds.
    pub min_length: u64,
    pub codec: String,
    pub title: String,
    pub album: String,
    pub artist: String,
}

impl SearchParams {
    pub fn new(query: impl Into<String>) -> Self {
        SearchParams {
            query: query.into(),
            ..Default::default()
        }
    }
}

/// A search request's payload (`CreateSearchData` with `WriteSearchPacket`),
/// and whether it holds a 64-bit number (then the server must support
/// large files).
pub fn encode_search(
    params: &SearchParams,
    supports_64bit: bool,
) -> Result<(Vec<u8>, bool), QueryError> {
    let expr = parse_query(&params.query)?;
    Ok(write_search(params, &expr, supports_64bit))
}

/// What a Kad keyword search needs: its keyword (the first of
/// [`kad_words`], maybe replaced by a longer word of the query) and the
/// search terms (`CreateSearchData(KadSearch)`; empty when the keyword says
/// it all). Kad always takes 64-bit sizes.
pub fn encode_kad_search(params: &SearchParams) -> Result<(String, Vec<u8>), QueryError> {
    let Some(first) = kad_words(&params.query).into_iter().next() else {
        return Err(QueryError::NoKeyword);
    };
    let (expr, keyword) = parse_query_kad(&params.query, &first)?;
    Ok((keyword, write_search(params, &expr, true).0))
}

/// `WriteSearchPacket`
fn write_search(params: &SearchParams, expr: &[Term], supports_64bit: bool) -> (Vec<u8>, bool) {
    let mut w = Writer::new();
    let mut using_64bit = false;

    let string = |w: &mut Writer, s: &str, enc: StrEncoding| {
        w.string(s, enc, LenField::U16);
    };
    let op = |w: &mut Writer, code: u8| {
        w.u8(0).u8(code);
    };

    enum Extra<'a> {
        Text(u8, &'a str, StrEncoding),
        Num(u8, SearchCompare, u64),
    }
    let mut extras: Vec<Extra> = Vec::new();
    if let Some(ft) = params.file_type {
        // The historical simple-search mapping of archives and CD images.
        let ft = match ft {
            FileType::Archive | FileType::CdImage if expr.len() <= 1 => FileType::Program,
            ft => ft,
        };
        extras.push(Extra::Text(
            FileTag::Filetype.into(),
            ft.as_str(),
            StrEncoding::Latin1,
        ));
    }
    let mut num = |tag: FileTag, cmp: SearchCompare, v: u64| {
        if v > 0 {
            extras.push(Extra::Num(tag.into(), cmp, v));
        }
    };
    num(FileTag::Filesize, SearchCompare::Greater, params.min_size);
    num(FileTag::Filesize, SearchCompare::Less, params.max_size);
    num(
        FileTag::Sources,
        SearchCompare::Greater,
        params.availability,
    );
    // Then text and numbers, interleaved in WriteSearchPacket's order.
    let mut rest: Vec<Extra> = Vec::new();
    if !params.extension.is_empty() {
        rest.push(Extra::Text(
            FileTag::Fileformat.into(),
            &params.extension,
            StrEncoding::Utf8,
        ));
    }
    if params.min_bitrate > 0 {
        rest.push(Extra::Num(
            FileTag::MediaBitrate.into(),
            SearchCompare::GreaterEqual,
            params.min_bitrate,
        ));
    }
    if params.min_length > 0 {
        rest.push(Extra::Num(
            FileTag::MediaLength.into(),
            SearchCompare::GreaterEqual,
            params.min_length,
        ));
    }
    for (tag, v) in [
        (FileTag::MediaCodec, &params.codec),
        (FileTag::MediaTitle, &params.title),
        (FileTag::MediaAlbum, &params.album),
        (FileTag::MediaArtist, &params.artist),
    ] {
        if !v.is_empty() {
            rest.push(Extra::Text(tag.into(), v, StrEncoding::Utf8));
        }
    }
    extras.extend(rest);

    let mut write_extra = |w: &mut Writer, e: &Extra| match *e {
        Extra::Text(tag, s, enc) => {
            w.u8(2);
            string(w, s, enc);
            w.u16(1).u8(tag);
        }
        Extra::Num(tag, cmp, v) => {
            if v > u32::MAX as u64 && supports_64bit {
                using_64bit = true;
                w.u8(8).u64(v);
            } else {
                w.u8(3).u32(v.min(u32::MAX as u64) as u32);
            }
            w.u8(cmp.into()).u16(1).u8(tag);
        }
    };
    let write_expr = |w: &mut Writer| {
        for t in expr {
            match t {
                Term::And => op(w, 0),
                Term::Or => op(w, 1),
                Term::Not => op(w, 2),
                Term::Word(s) => {
                    w.u8(1);
                    string(w, s, StrEncoding::Utf8);
                }
            }
        }
    };

    let has_expr = !expr.is_empty();
    let n = usize::from(has_expr) + extras.len();
    if expr.len() <= 1 {
        // AND t0 AND t1 ... tn: an AND in front of every term but the last.
        let mut i = 0;
        if has_expr {
            if i + 1 < n {
                op(&mut w, 0);
            }
            write_expr(&mut w);
            i += 1;
        }
        for e in &extras {
            if i + 1 < n {
                op(&mut w, 0);
            }
            write_extra(&mut w, e);
            i += 1;
        }
    } else {
        for _ in 1..n {
            op(&mut w, 0);
        }
        write_expr(&mut w);
        for e in &extras {
            write_extra(&mut w, e);
        }
    }
    (w.into_bytes(), using_64bit)
}

/// One file of a search answer (`CSearchFile`).
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    pub hash: Md4Hash,
    /// A client that has it, as the server says (0 when it gives none or a bad one).
    pub client_id: u32,
    pub client_port: u16,
    pub name: String,
    pub size: u64,
    pub sources: u32,
    pub complete_sources: u32,
    /// The type string (`Audio`, `Video`, ...), when given as one.
    pub file_type: Option<String>,
    /// 0 to 5, from the server's packed rating.
    pub rating: u8,
    /// Every tag, as received.
    pub tags: Vec<Tag>,
}

/// What can be wrong with an answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnswerError {
    #[error("truncated search answer: {0}")]
    Truncated(String),
}

impl SearchResult {
    /// Read one result.
    pub fn read(r: &mut Reader<'_>) -> Result<SearchResult, AnswerError> {
        let e = |e: &dyn std::fmt::Display| AnswerError::Truncated(e.to_string());
        let hash = r.hash().map_err(|x| e(&x))?;
        let mut client_id = r.u32().map_err(|x| e(&x))?;
        let mut client_port = r.u16().map_err(|x| e(&x))?;
        if client_id == 0 || client_port == 0 {
            client_id = 0;
            client_port = 0;
        }
        let count = r.u32().map_err(|x| e(&x))?;
        let mut res = SearchResult {
            hash,
            client_id,
            client_port,
            name: String::new(),
            size: 0,
            sources: 0,
            complete_sources: 0,
            file_type: None,
            rating: 0,
            tags: Vec::new(),
        };
        // Every tag takes at least 3 bytes: do not trust the count.
        for _ in 0..count {
            let tag = Tag::read_ed2k(r, true, true).map_err(|x| e(&x))?;
            let int = tag.as_int().unwrap_or(0);
            let id = match tag.name.as_bytes() {
                [id] => FileTag::try_from(*id).ok(),
                _ => None,
            };
            match id {
                Some(FileTag::Filename) => {
                    res.name = tag.as_str().unwrap_or_default().to_owned();
                }
                Some(FileTag::Filesize) => {
                    res.size = (res.size & !0xFFFF_FFFF) | (int & 0xFFFF_FFFF)
                }
                Some(FileTag::FilesizeHi) => res.size = (int << 32) + (res.size & 0xFFFF_FFFF),
                Some(FileTag::Sources) => res.sources = int as u32,
                Some(FileTag::CompleteSources) => res.complete_sources = int as u32,
                Some(FileTag::Filetype) => res.file_type = tag.as_str().map(str::to_owned),
                Some(FileTag::FileRating) => res.rating = ((int & 0xF) / 3) as u8,
                _ => {}
            }
            res.tags.push(tag);
        }
        Ok(res)
    }
}

/// `OP_SEARCHRESULT`: `<count 4>(result)[count]`, then, from some servers,
/// a byte saying whether more results can be asked for
/// (`OP_QUERY_MORE_RESULT`).
pub fn parse_search_answer(
    payload: &[u8],
) -> Result<(Vec<SearchResult>, Option<bool>), AnswerError> {
    let mut r = Reader::new(payload);
    let count = r.u32().map_err(|e| AnswerError::Truncated(e.to_string()))?;
    let mut out = Vec::new();
    for _ in 0..count {
        out.push(SearchResult::read(&mut r)?);
    }
    let more = match r.rest() {
        [b] => Some(*b != 0),
        _ => None,
    };
    Ok((out, more))
}
