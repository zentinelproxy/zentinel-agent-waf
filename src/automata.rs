//! Automata-based pattern matching engine
//!
//! Uses RegexSet for efficient multi-pattern matching. Instead of iterating
//! through 200+ rules sequentially, this module compiles patterns into regex sets
//! grouped by target location and paranoia level for single-pass matching.
//!
//! Unlike regex-automata's MetaRegex which uses leftmost-first semantics,
//! RegexSet reports ALL patterns that match, which is essential for WAF
//! detection where multiple attack patterns may overlap.

use anyhow::{Context, Result};
use regex::{Regex, RegexSet};
use regex_automata::PatternID;
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::rules::{Rule, Severity, Target};

/// Target group for automata organization
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TargetGroup {
    Body,
    Query,
    Headers,
    Path,
    Cookie,
    /// Rules with Target::All
    All,
}

impl TargetGroup {
    /// Convert a location string to a target group
    pub fn from_location(location: &str) -> Self {
        if location == "path" {
            TargetGroup::Path
        } else if location == "query" {
            TargetGroup::Query
        } else if location.starts_with("header:") {
            TargetGroup::Headers
        } else if location.starts_with("cookie:") {
            TargetGroup::Cookie
        } else if location == "body" || location == "response_body" {
            TargetGroup::Body
        } else {
            TargetGroup::All
        }
    }
}

impl From<&Target> for TargetGroup {
    fn from(target: &Target) -> Self {
        match target {
            Target::Body => TargetGroup::Body,
            Target::QueryString => TargetGroup::Query,
            Target::AllHeaders | Target::Header(_) => TargetGroup::Headers,
            Target::Path => TargetGroup::Path,
            Target::Cookie => TargetGroup::Cookie,
            Target::All => TargetGroup::All,
        }
    }
}

/// Key for automata grouping
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct AutomataGroupKey {
    pub target: TargetGroup,
    pub max_paranoia: u8,
}

/// Compiled automaton for a group of patterns
pub struct CompiledAutomaton {
    /// RegexSet for matching all patterns that match (supports overlapping)
    pub regex_set: RegexSet,
    /// Individual regexes for extracting match positions
    pub regexes: Vec<Regex>,
    /// Map pattern index to rule ID
    pub pattern_to_rule: Vec<u32>,
}

/// Lightweight rule metadata (excludes compiled Regex for memory efficiency)
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub id: u32,
    pub name: String,
    pub attack_type: crate::rules::AttackType,
    pub severity: Severity,
    pub confidence: crate::rules::Confidence,
    pub base_score: u32,
    pub tags: Vec<String>,
}

impl From<&Rule> for RuleMetadata {
    fn from(rule: &Rule) -> Self {
        Self {
            id: rule.id,
            name: rule.name.clone(),
            attack_type: rule.attack_type,
            severity: rule.severity,
            confidence: rule.confidence,
            base_score: rule.base_score,
            tags: rule.tags.clone(),
        }
    }
}

/// Result of automata matching
#[derive(Debug)]
pub struct AutomataMatch {
    pub rule_id: u32,
    pub pattern_id: PatternID,
    pub start: usize,
    pub end: usize,
}

/// Automata-based pattern matching engine
pub struct AutomataEngine {
    /// Grouped automata by (target, paranoia)
    groups: HashMap<AutomataGroupKey, CompiledAutomaton>,
    /// Rules indexed by ID for metadata lookup
    rules_by_id: HashMap<u32, RuleMetadata>,
    /// Whether automata compilation succeeded
    enabled: bool,
}

impl AutomataEngine {
    /// Compile rules into grouped automata
    pub fn compile(rules: &[Rule], max_paranoia: u8) -> Result<Self> {
        let mut pattern_groups: HashMap<AutomataGroupKey, Vec<(u32, String)>> = HashMap::new();
        let mut rules_by_id = HashMap::new();

        // Group patterns by (target, paranoia)
        for rule in rules {
            if rule.paranoia_level > max_paranoia {
                continue;
            }

            // Store rule metadata
            rules_by_id.insert(rule.id, RuleMetadata::from(rule));

            // Get effective targets for this rule
            let targets = if rule.targets.is_empty() {
                vec![Target::All]
            } else {
                rule.targets.clone()
            };

            // Add to each applicable target group
            for target in &targets {
                let target_group = TargetGroup::from(target);

                // Add pattern to all paranoia levels up to rule's level
                for paranoia in rule.paranoia_level..=max_paranoia {
                    let key = AutomataGroupKey {
                        target: target_group.clone(),
                        max_paranoia: paranoia,
                    };
                    pattern_groups
                        .entry(key)
                        .or_default()
                        .push((rule.id, rule.pattern_str.clone()));
                }
            }
        }

        // Compile each group into an automaton
        let mut groups = HashMap::new();
        let mut total_patterns = 0;
        let mut failed_groups = 0;

        for (key, patterns) in pattern_groups {
            match Self::compile_group(&patterns) {
                Ok(automaton) => {
                    total_patterns += patterns.len();
                    groups.insert(key, automaton);
                }
                Err(e) => {
                    warn!(
                        target = ?key.target,
                        paranoia = key.max_paranoia,
                        error = %e,
                        "Failed to compile automaton group, will fallback to sequential matching"
                    );
                    failed_groups += 1;
                }
            }
        }

        let enabled = !groups.is_empty();

        info!(
            groups = groups.len(),
            patterns = total_patterns,
            failed_groups = failed_groups,
            enabled = enabled,
            "Automata engine compiled"
        );

        Ok(Self {
            groups,
            rules_by_id,
            enabled,
        })
    }

    /// Compile a group of patterns into a single automaton
    fn compile_group(patterns: &[(u32, String)]) -> Result<CompiledAutomaton> {
        if patterns.is_empty() {
            anyhow::bail!("Cannot compile empty pattern group");
        }

        let pattern_strs: Vec<&str> = patterns.iter().map(|(_, p)| p.as_str()).collect();
        let pattern_to_rule: Vec<u32> = patterns.iter().map(|(id, _)| *id).collect();

        // Build RegexSet for efficient multi-pattern matching
        // RegexSet reports ALL patterns that match, unlike MetaRegex which uses leftmost-first
        let regex_set = RegexSet::new(&pattern_strs).context("Failed to compile RegexSet")?;

        // Also compile individual regexes for extracting match positions
        // RegexSet only tells us WHICH patterns match, not WHERE
        let regexes: Result<Vec<Regex>, _> = pattern_strs.iter().map(|p| Regex::new(p)).collect();
        let regexes = regexes.context("Failed to compile individual regexes")?;

        Ok(CompiledAutomaton {
            regex_set,
            regexes,
            pattern_to_rule,
        })
    }

    /// Check if automata engine is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Find all matches in input for a given location
    pub fn find_all(&self, input: &str, location: &str, paranoia: u8) -> Vec<AutomataMatch> {
        if !self.enabled {
            return Vec::new();
        }

        let target_group = TargetGroup::from_location(location);
        let mut results = Vec::new();
        let mut seen_rules: std::collections::HashSet<u32> = std::collections::HashSet::new();

        // Check target-specific automaton
        let key = AutomataGroupKey {
            target: target_group.clone(),
            max_paranoia: paranoia,
        };
        if let Some(automaton) = self.groups.get(&key) {
            self.find_in_automaton(automaton, input, &mut results, &mut seen_rules);
        }

        // Check Target::All automaton (rules that apply to all locations)
        if target_group != TargetGroup::All {
            let all_key = AutomataGroupKey {
                target: TargetGroup::All,
                max_paranoia: paranoia,
            };
            if let Some(automaton) = self.groups.get(&all_key) {
                self.find_in_automaton(automaton, input, &mut results, &mut seen_rules);
            }
        }

        debug!(
            location = location,
            paranoia = paranoia,
            matches = results.len(),
            "Automata scan complete"
        );

        results
    }

    /// Find matches in a single automaton using RegexSet
    fn find_in_automaton(
        &self,
        automaton: &CompiledAutomaton,
        input: &str,
        results: &mut Vec<AutomataMatch>,
        seen_rules: &mut std::collections::HashSet<u32>,
    ) {
        // Use RegexSet to find ALL patterns that match (including overlapping)
        let matching_patterns: Vec<usize> =
            automaton.regex_set.matches(input).into_iter().collect();

        // For each matching pattern, get the match position using the individual regex
        for pattern_idx in matching_patterns {
            let rule_id = automaton.pattern_to_rule[pattern_idx];

            // Deduplicate by rule ID (same rule may be in multiple groups)
            if seen_rules.insert(rule_id) {
                // Get match position using the individual regex
                let (start, end) = if let Some(m) = automaton.regexes[pattern_idx].find(input) {
                    (m.start(), m.end())
                } else {
                    // Should not happen, but fallback to full input range
                    (0, input.len())
                };

                results.push(AutomataMatch {
                    rule_id,
                    pattern_id: PatternID::new_unchecked(pattern_idx),
                    start,
                    end,
                });
            }
        }
    }

    /// Get rule metadata by ID
    pub fn get_rule_metadata(&self, rule_id: u32) -> Option<&RuleMetadata> {
        self.rules_by_id.get(&rule_id)
    }

    /// Get number of compiled groups
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Get total number of patterns across all groups
    pub fn pattern_count(&self) -> usize {
        self.groups.values().map(|g| g.pattern_to_rule.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{AttackType, Confidence, RuleBuilder, Severity};

    fn make_test_rules() -> Vec<Rule> {
        vec![
            RuleBuilder::new(942100, "SQL Injection: UNION SELECT")
                .attack_type(AttackType::SqlInjection)
                .severity(Severity::Critical)
                .confidence(Confidence::High)
                .paranoia(1)
                .pattern(r"(?i)\bUNION\b.*\bSELECT\b")
                .base_score(9)
                .targets(vec![Target::QueryString, Target::Body])
                .build()
                .unwrap(),
            RuleBuilder::new(941100, "XSS: Script Tag")
                .attack_type(AttackType::Xss)
                .severity(Severity::High)
                .confidence(Confidence::High)
                .paranoia(1)
                .pattern(r"(?i)<script[^>]*>")
                .base_score(8)
                .targets(vec![Target::All])
                .build()
                .unwrap(),
            RuleBuilder::new(942110, "SQL Injection: OR 1=1")
                .attack_type(AttackType::SqlInjection)
                .severity(Severity::High)
                .confidence(Confidence::Medium)
                .paranoia(2)
                .pattern(r"(?i)'\s*OR\s*'1'\s*=\s*'1")
                .base_score(7)
                .targets(vec![Target::QueryString])
                .build()
                .unwrap(),
        ]
    }

    #[test]
    fn test_automata_compilation() {
        let rules = make_test_rules();
        let engine = AutomataEngine::compile(&rules, 2).unwrap();

        assert!(engine.is_enabled());
        assert!(engine.group_count() > 0);
    }

    #[test]
    fn test_automata_matching() {
        let rules = make_test_rules();
        let engine = AutomataEngine::compile(&rules, 2).unwrap();

        // Should match SQL injection
        let matches = engine.find_all("id=1 UNION SELECT * FROM users", "query", 2);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.rule_id == 942100));

        // Should match XSS
        let matches = engine.find_all("<script>alert('xss')</script>", "body", 2);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.rule_id == 941100));
    }

    #[test]
    fn test_paranoia_filtering() {
        let rules = make_test_rules();
        let engine = AutomataEngine::compile(&rules, 1).unwrap();

        // Paranoia 2 rule should not match at paranoia 1
        let matches = engine.find_all("' OR '1'='1", "query", 1);
        assert!(!matches.iter().any(|m| m.rule_id == 942110));
    }

    #[test]
    fn test_target_filtering() {
        let rules = make_test_rules();
        let engine = AutomataEngine::compile(&rules, 2).unwrap();

        // UNION SELECT should match in query
        let matches = engine.find_all("UNION SELECT", "query", 2);
        assert!(matches.iter().any(|m| m.rule_id == 942100));

        // Script tag (Target::All) should match anywhere
        let matches = engine.find_all("<script>", "path", 2);
        assert!(matches.iter().any(|m| m.rule_id == 941100));
    }

    #[test]
    fn test_rule_metadata_lookup() {
        let rules = make_test_rules();
        let engine = AutomataEngine::compile(&rules, 2).unwrap();

        let metadata = engine.get_rule_metadata(942100).unwrap();
        assert_eq!(metadata.name, "SQL Injection: UNION SELECT");
        assert_eq!(metadata.attack_type, AttackType::SqlInjection);
        assert_eq!(metadata.base_score, 9);
    }

    #[test]
    fn test_match_extraction() {
        let rules = make_test_rules();
        let engine = AutomataEngine::compile(&rules, 2).unwrap();

        let input = "test UNION SELECT * FROM users";
        let matches = engine.find_all(input, "query", 2);

        if let Some(m) = matches.iter().find(|m| m.rule_id == 942100) {
            let matched_text = &input[m.start..m.end];
            assert!(matched_text.contains("UNION"));
            assert!(matched_text.contains("SELECT"));
        }
    }

    #[test]
    fn test_target_all_rules() {
        // Test that rules with Target::All are found in all locations
        let rules = vec![
            // Rule with Target::All (explicitly set)
            RuleBuilder::new(999001, "Test: All Locations Rule")
                .attack_type(AttackType::XpathInjection)
                .severity(Severity::High)
                .confidence(Confidence::High)
                .paranoia(1)
                .pattern(r"(?i)'\s*or\s*'[^']*'\s*=\s*'") // XPath pattern
                .base_score(8)
                .targets(vec![Target::All])
                .build()
                .unwrap(),
            // Rule with no targets (should also apply to all)
            RuleBuilder::new(999002, "Test: No Targets Rule")
                .attack_type(AttackType::XpathInjection)
                .severity(Severity::High)
                .confidence(Confidence::High)
                .paranoia(1)
                .pattern(r"(?i)/etc/passwd")
                .base_score(8)
                .build()
                .unwrap(),
        ];

        let engine = AutomataEngine::compile(&rules, 2).unwrap();

        eprintln!("Groups: {:?}", engine.groups.keys().collect::<Vec<_>>());

        // Test rule 999001 with Target::All
        let input1 = "id=' OR '1'='1";
        let matches_query = engine.find_all(input1, "query", 1);
        let matches_body = engine.find_all(input1, "body", 1);
        let matches_path = engine.find_all(input1, "path", 1);

        eprintln!("input='{}' query matches: {:?}", input1, matches_query);
        eprintln!("input='{}' body matches: {:?}", input1, matches_body);
        eprintln!("input='{}' path matches: {:?}", input1, matches_path);

        assert!(
            matches_query.iter().any(|m| m.rule_id == 999001),
            "Target::All rule should match in query"
        );
        assert!(
            matches_body.iter().any(|m| m.rule_id == 999001),
            "Target::All rule should match in body"
        );
        assert!(
            matches_path.iter().any(|m| m.rule_id == 999001),
            "Target::All rule should match in path"
        );

        // Test rule 999002 with no targets (empty vec)
        let input2 = "/files/../../../etc/passwd";
        let matches_path2 = engine.find_all(input2, "path", 1);

        eprintln!("input='{}' path matches: {:?}", input2, matches_path2);

        assert!(
            matches_path2.iter().any(|m| m.rule_id == 999002),
            "Empty targets rule should match in path"
        );
    }

    #[test]
    fn test_xpath_pattern_directly() {
        // Test the XPath pattern directly with RegexSet
        use regex::RegexSet;

        let pattern = r"(?i)'\s*or\s*'[^']*'\s*=\s*'";
        let input = "id=' OR '1'='1";

        // First verify regex crate matches
        let re = regex::Regex::new(pattern).unwrap();
        assert!(re.is_match(input), "regex crate should match");

        // Now test RegexSet
        let regex_set = RegexSet::new([pattern]).unwrap();
        let matches: Vec<_> = regex_set.matches(input).into_iter().collect();
        eprintln!(
            "Direct pattern test: input='{}', matches={:?}",
            input, matches
        );
        assert!(!matches.is_empty(), "RegexSet should match");
    }

    #[test]
    fn test_regexset_overlapping() {
        // Test that RegexSet finds multiple overlapping patterns
        use regex::RegexSet;

        let patterns = [
            r"(?i)'\s*or\s*'[^']*'\s*=\s*'", // XPath pattern
            r"(?i)'\s*OR\s*",                // SQL injection pattern
        ];
        let input = "id=' OR '1'='1";

        let regex_set = RegexSet::new(patterns).unwrap();
        let matches: Vec<_> = regex_set.matches(input).into_iter().collect();
        eprintln!("Overlapping test: input='{}', matches={:?}", input, matches);

        // Both patterns should match
        assert_eq!(matches.len(), 2, "Both patterns should match the input");
    }
}
