//! MITRE ATLAS technique IDs used by the built-in rule crosswalk.

pub const VERSION: &str = "2026.09";

const TECHNIQUES: &[&str] = &[
    "AML.T0025",
    "AML.T0050",
    "AML.T0051.001",
    "AML.T0054",
    "AML.T0057",
    "AML.T0068",
    "AML.T0080",
    "AML.T0081",
    "AML.T0083",
    "AML.T0098",
];

pub fn is_known_technique(id: &str) -> bool {
    TECHNIQUES.contains(&id)
}
