//! A small, type-checked condition language for scoring rules.
//!
//! ```text
//! in_git && untracked && !in_dependency_dir
//! location == "downloads"
//! has_parent && content >= parent_content + 30
//! shadows && finding("PI001", "PI004")
//! ```
//!
//! Operators, loosest first: `||`, `&&`, `!`, comparisons (`== != < <= > >=`),
//! `+ -`. Literals are integers, `"strings"`, `true` and `false`. Functions:
//! `finding("ID", ...)`, `contains(text, "needle")` (case-insensitive) and
//! `matches(text, "regex")`. Expressions are checked when they are compiled,
//! so an unknown name or a type mismatch is a config error, not a rule that
//! silently never fires.

use anyhow::{anyhow, bail, Result};
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Bool,
    Int,
    Str,
}

impl Ty {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ty::Bool => "bool",
            Ty::Int => "int",
            Ty::Str => "string",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Str(String),
}

impl Value {
    fn ty(&self) -> Ty {
        match self {
            Value::Bool(_) => Ty::Bool,
            Value::Int(_) => Ty::Int,
            Value::Str(_) => Ty::Str,
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::Str(s) => f.write_str(s),
        }
    }
}

/// What an expression can read: named values plus the IDs of the static findings.
pub trait Env {
    fn get(&self, name: &str) -> Option<Value>;
    fn has_finding(&self, id: &str) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
enum Node {
    Lit(Value),
    Var(String),
    Not(Box<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Cmp(Cmp, Box<Node>, Box<Node>),
    Add(Box<Node>, Box<Node>),
    Sub(Box<Node>, Box<Node>),
    Finding(Vec<String>),
    Contains(Box<Node>, Box<Node>),
    Matches(Box<Node>, Regex),
}

/// A compiled boolean expression.
#[derive(Debug, Clone)]
pub struct Expr {
    root: Node,
}

impl Expr {
    /// Parse and type-check `src`. `schema` returns the type of a variable, or None if it doesn't exist.
    pub fn compile(src: &str, schema: &dyn Fn(&str) -> Option<Ty>) -> Result<Expr> {
        let tokens = lex(src)?;
        let mut p = Parser { t: &tokens, i: 0 };
        let root = p.or()?;
        if p.i < tokens.len() {
            bail!("unexpected {} at position {}", tokens[p.i].0.describe(), tokens[p.i].1);
        }
        match check(&root, schema)? {
            Ty::Bool => Ok(Expr { root }),
            t => bail!("condition must be true/false, but it is a {}", t.as_str()),
        }
    }

    pub fn eval(&self, env: &dyn Env) -> bool {
        matches!(eval(&self.root, env), Value::Bool(true))
    }
}

fn check(n: &Node, schema: &dyn Fn(&str) -> Option<Ty>) -> Result<Ty> {
    let want = |n: &Node, t: Ty, what: &str| -> Result<()> {
        let got = check(n, schema)?;
        if got != t {
            bail!("{what} needs a {}, got a {}", t.as_str(), got.as_str());
        }
        Ok(())
    };
    Ok(match n {
        Node::Lit(v) => v.ty(),
        Node::Var(name) => schema(name).ok_or_else(|| anyhow!("unknown name `{name}`"))?,
        Node::Not(a) => {
            want(a, Ty::Bool, "`!`")?;
            Ty::Bool
        }
        Node::And(a, b) | Node::Or(a, b) => {
            want(a, Ty::Bool, "`&&`/`||`")?;
            want(b, Ty::Bool, "`&&`/`||`")?;
            Ty::Bool
        }
        Node::Add(a, b) | Node::Sub(a, b) => {
            want(a, Ty::Int, "`+`/`-`")?;
            want(b, Ty::Int, "`+`/`-`")?;
            Ty::Int
        }
        Node::Cmp(op, a, b) => {
            let (ta, tb) = (check(a, schema)?, check(b, schema)?);
            if ta != tb {
                bail!("cannot compare a {} with a {}", ta.as_str(), tb.as_str());
            }
            if ta != Ty::Int && !matches!(op, Cmp::Eq | Cmp::Ne) {
                bail!("`<`, `<=`, `>` and `>=` need numbers, got a {}", ta.as_str());
            }
            Ty::Bool
        }
        Node::Finding(_) => Ty::Bool,
        Node::Contains(a, b) => {
            want(a, Ty::Str, "contains()")?;
            want(b, Ty::Str, "contains()")?;
            Ty::Bool
        }
        Node::Matches(a, _) => {
            want(a, Ty::Str, "matches()")?;
            Ty::Bool
        }
    })
}

fn eval(n: &Node, env: &dyn Env) -> Value {
    let int = |n: &Node| match eval(n, env) {
        Value::Int(i) => i,
        _ => 0,
    };
    let text = |n: &Node| match eval(n, env) {
        Value::Str(s) => s,
        v => v.to_string(),
    };
    let truth = |n: &Node| matches!(eval(n, env), Value::Bool(true));
    match n {
        Node::Lit(v) => v.clone(),
        // Compilation checked the name exists, so a miss here is an Env bug; treat it as false.
        Node::Var(name) => env.get(name).unwrap_or(Value::Bool(false)),
        Node::Not(a) => Value::Bool(!truth(a)),
        Node::And(a, b) => Value::Bool(truth(a) && truth(b)),
        Node::Or(a, b) => Value::Bool(truth(a) || truth(b)),
        Node::Add(a, b) => Value::Int(int(a).saturating_add(int(b))),
        Node::Sub(a, b) => Value::Int(int(a).saturating_sub(int(b))),
        Node::Cmp(op, a, b) => {
            let (x, y) = (eval(a, env), eval(b, env));
            Value::Bool(match (op, &x, &y) {
                (Cmp::Eq, _, _) => x == y,
                (Cmp::Ne, _, _) => x != y,
                (_, Value::Int(x), Value::Int(y)) => match op {
                    Cmp::Lt => x < y,
                    Cmp::Le => x <= y,
                    Cmp::Gt => x > y,
                    _ => x >= y,
                },
                _ => false,
            })
        }
        Node::Finding(ids) => Value::Bool(ids.iter().any(|id| env.has_finding(id))),
        Node::Contains(a, b) => Value::Bool(text(a).to_lowercase().contains(&text(b).to_lowercase())),
        Node::Matches(a, re) => Value::Bool(re.is_match(&text(a))),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Int(i64),
    Str(String),
    Op(&'static str),
}

impl Tok {
    fn describe(&self) -> String {
        match self {
            Tok::Ident(s) => format!("`{s}`"),
            Tok::Int(i) => format!("`{i}`"),
            Tok::Str(s) => format!("\"{s}\""),
            Tok::Op(o) => format!("`{o}`"),
        }
    }
}

const OPS: &[&str] = &["&&", "||", "==", "!=", ">=", "<=", "!", "<", ">", "+", "-", "(", ")", ","];

fn lex(src: &str) -> Result<Vec<(Tok, usize)>> {
    let mut out = Vec::new();
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let start = i;
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() {
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let n = src[start..i].parse().map_err(|_| anyhow!("number too large at position {start}"))?;
            out.push((Tok::Int(n), start));
        } else if c.is_ascii_alphabetic() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push((Tok::Ident(src[start..i].to_string()), start));
        } else if c == b'"' {
            let mut s = String::new();
            let mut chars = src[i + 1..].char_indices();
            loop {
                match chars.next() {
                    None => bail!("unterminated string starting at position {start}"),
                    Some((j, '"')) => {
                        i += j + 2;
                        break;
                    }
                    Some((_, '\\')) => match chars.next() {
                        Some((_, ch)) => s.push(ch),
                        None => bail!("unterminated string starting at position {start}"),
                    },
                    Some((_, ch)) => s.push(ch),
                }
            }
            out.push((Tok::Str(s), start));
        } else if let Some(op) = OPS.iter().find(|op| src[i..].starts_with(**op)) {
            i += op.len();
            out.push((Tok::Op(op), start));
        } else {
            let ch = src[i..].chars().next().unwrap_or('?');
            bail!("unexpected character '{ch}' at position {start}");
        }
    }
    Ok(out)
}

struct Parser<'a> {
    t: &'a [(Tok, usize)],
    i: usize,
}

impl Parser<'_> {
    fn peek_op(&self, op: &str) -> bool {
        matches!(self.t.get(self.i), Some((Tok::Op(o), _)) if *o == op)
    }

    fn eat(&mut self, op: &str) -> bool {
        let hit = self.peek_op(op);
        if hit {
            self.i += 1;
        }
        hit
    }

    fn expect(&mut self, op: &str) -> Result<()> {
        if self.eat(op) {
            return Ok(());
        }
        match self.t.get(self.i) {
            Some((t, pos)) => bail!("expected `{op}` but found {} at position {pos}", t.describe()),
            None => bail!("expected `{op}` but the condition ended"),
        }
    }

    fn or(&mut self) -> Result<Node> {
        let mut n = self.and()?;
        while self.eat("||") {
            n = Node::Or(Box::new(n), Box::new(self.and()?));
        }
        Ok(n)
    }

    fn and(&mut self) -> Result<Node> {
        let mut n = self.not()?;
        while self.eat("&&") {
            n = Node::And(Box::new(n), Box::new(self.not()?));
        }
        Ok(n)
    }

    fn not(&mut self) -> Result<Node> {
        if self.eat("!") {
            return Ok(Node::Not(Box::new(self.not()?)));
        }
        self.cmp()
    }

    fn cmp(&mut self) -> Result<Node> {
        let a = self.sum()?;
        let op = [
            ("==", Cmp::Eq),
            ("!=", Cmp::Ne),
            (">=", Cmp::Ge),
            ("<=", Cmp::Le),
            (">", Cmp::Gt),
            ("<", Cmp::Lt),
        ]
        .into_iter()
        .find(|(s, _)| self.peek_op(s));
        match op {
            Some((s, op)) => {
                self.expect(s)?;
                Ok(Node::Cmp(op, Box::new(a), Box::new(self.sum()?)))
            }
            None => Ok(a),
        }
    }

    fn sum(&mut self) -> Result<Node> {
        let mut n = self.atom()?;
        loop {
            if self.eat("+") {
                n = Node::Add(Box::new(n), Box::new(self.atom()?));
            } else if self.eat("-") {
                n = Node::Sub(Box::new(n), Box::new(self.atom()?));
            } else {
                return Ok(n);
            }
        }
    }

    fn atom(&mut self) -> Result<Node> {
        let Some((tok, pos)) = self.t.get(self.i).cloned() else {
            bail!("the condition ended unexpectedly");
        };
        self.i += 1;
        match tok {
            Tok::Int(i) => Ok(Node::Lit(Value::Int(i))),
            Tok::Str(s) => Ok(Node::Lit(Value::Str(s))),
            Tok::Op("(") => {
                let n = self.or()?;
                self.expect(")")?;
                Ok(n)
            }
            Tok::Ident(name) if self.peek_op("(") => {
                self.i += 1;
                let mut args = Vec::new();
                if !self.eat(")") {
                    loop {
                        args.push(self.or()?);
                        if self.eat(")") {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                call(&name, args)
            }
            Tok::Ident(name) => Ok(match name.as_str() {
                "true" => Node::Lit(Value::Bool(true)),
                "false" => Node::Lit(Value::Bool(false)),
                _ => Node::Var(name),
            }),
            t => bail!("unexpected {} at position {pos}", t.describe()),
        }
    }
}

fn literal(n: &Node) -> Option<&str> {
    match n {
        Node::Lit(Value::Str(s)) => Some(s),
        _ => None,
    }
}

fn call(name: &str, mut args: Vec<Node>) -> Result<Node> {
    match name {
        "finding" => {
            if args.is_empty() {
                bail!("finding() needs at least one rule ID, e.g. finding(\"PI001\")");
            }
            let ids = args
                .iter()
                .map(|a| literal(a).map(|s| s.to_ascii_uppercase()))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| anyhow!("finding() takes quoted rule IDs, e.g. finding(\"PI001\")"))?;
            Ok(Node::Finding(ids))
        }
        "contains" | "matches" if args.len() != 2 => bail!("{name}() takes 2 arguments, got {}", args.len()),
        "contains" => {
            let b = args.pop().unwrap();
            let a = args.pop().unwrap();
            Ok(Node::Contains(Box::new(a), Box::new(b)))
        }
        "matches" => {
            let pat = literal(&args[1]).ok_or_else(|| anyhow!("matches() needs a quoted regex as its second argument"))?;
            let re = Regex::new(pat).map_err(|e| anyhow!("bad regex in matches(): {e}"))?;
            Ok(Node::Matches(Box::new(args.swap_remove(0)), re))
        }
        _ => bail!("unknown function `{name}()` (available: finding, contains, matches)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl Env for E {
        fn get(&self, name: &str) -> Option<Value> {
            match name {
                "yes" => Some(Value::Bool(true)),
                "no" => Some(Value::Bool(false)),
                "n" => Some(Value::Int(40)),
                "s" => Some(Value::Str("Downloads/x".into())),
                _ => None,
            }
        }
        fn has_finding(&self, id: &str) -> bool {
            id == "PI001"
        }
    }

    fn schema(name: &str) -> Option<Ty> {
        E.get(name).map(|v| v.ty())
    }

    fn run(src: &str) -> bool {
        Expr::compile(src, &schema).unwrap_or_else(|e| panic!("{src}: {e}")).eval(&E)
    }

    fn err(src: &str) -> String {
        Expr::compile(src, &schema).unwrap_err().to_string()
    }

    #[test]
    fn evaluates() {
        assert!(run("yes && !no"));
        assert!(run("no || yes && yes"));
        assert!(!run("(no || yes) && no"));
        assert!(run("n >= 10 + 30"));
        assert!(!run("n > 50 - 9"));
        assert!(run("n - 50 < 0"));
        assert!(run("s != \"\" && contains(s, \"downloads\")"));
        assert!(run("matches(s, \"^Down\")"));
        assert!(run("finding(\"pi004\", \"PI001\")"));
        assert!(!run("finding(\"PI004\")"));
        assert!(run("true"));
    }

    #[test]
    fn rejects_bad_conditions() {
        assert!(err("typo && yes").contains("unknown name `typo`"));
        assert!(err("n").contains("must be true/false"));
        assert!(err("n == \"40\"").contains("cannot compare"));
        assert!(err("s > \"a\"").contains("need numbers"));
        assert!(err("yes &&").contains("ended unexpectedly"));
        assert!(err("(yes").contains("expected `)`"));
        assert!(err("yes & no").contains("unexpected character '&'"));
        assert!(err("nope(s)").contains("unknown function"));
        assert!(err("finding(s)").contains("quoted rule IDs"));
        assert!(err("matches(s, \"(\")").contains("bad regex"));
        assert!(err("yes no").contains("unexpected `no`"));
    }
}
