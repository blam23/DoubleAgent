# MITRE ATLAS rule crosswalk

The built-in analyzer and scoring rules carry an `atlas` array using the MITRE ATLAS v2026.09 technique IDs. The arrays are maintained beside each rule in `src/rules/analyzer.toml` and `src/rules/scoring.toml`. An empty array means there is no direct ATLAS technique mapping: a scanner or provenance heuristic is not itself an adversary technique.

These tags are a defensive cross-reference, not proof that a finding represents an observed adversary action. Several analyzer rules detect instructions that, if followed by an agent, would correspond to the tagged technique. The analyzer cannot establish that an agent followed them.

| ATLAS ID | Technique | Use in DoubleAgent |
|---|---|---|
| `AML.T0025` | Exfiltration via Cyber Means | Instructions to transfer or stage data to an external destination. |
| `AML.T0050` | Command and Scripting Interpreter | Instructions that invoke shell commands or scripts. |
| `AML.T0051.001` | LLM Prompt Injection: Indirect | Malicious instructions embedded in an agent instruction file or other ingested content. |
| `AML.T0054` | LLM Jailbreak | Role/mode hijacks and instructions to bypass safety controls. |
| `AML.T0057` | LLM Data Leakage | Instructions that direct protected data into output or toward an external destination. |
| `AML.T0068` | LLM Prompt Obfuscation | Hidden or encoded prompt content intended to evade human or automated review. |
| `AML.T0081` | Modify AI Agent Configuration | Instructions to change persistent agent settings or instruction files. |
| `AML.T0083` | Credentials from AI Agent Configuration | Instructions targeting credentials held in agent or tool configuration. |
| `AML.T0098` | AI Agent Tool Credential Harvesting | Instructions to retrieve credentials through available agent tools. |

The ATLAS version and technique IDs are validated when built-in rules load. Analyzer findings expose their technique IDs in JSON and SARIF; scoring reasons and `doubleagent config rules` also show mapped IDs. The exported finding JSON now includes an additive `atlas` array.
