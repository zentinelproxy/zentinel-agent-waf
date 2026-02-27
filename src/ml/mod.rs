//! ML-Based Attack Detection
//!
//! Provides machine learning capabilities for attack detection that can
//! catch attack variations that bypass traditional regex rules.
//!
//! # Architecture
//!
//! The ML system uses character n-grams as features, which are language-agnostic
//! and can detect obfuscation techniques like:
//! - Case variations (SeLeCt vs SELECT)
//! - Comment injection (SELECT/**/FROM)
//! - Encoding tricks (%53%45%4C%45%43%54)
//! - Character substitution
//!
//! # Modules
//!
//! - `ngram`: Character n-gram extraction
//! - `classifier`: Statistical attack classifier
//! - `fingerprint`: Request structural fingerprinting
//! - `similarity`: Payload embedding and similarity scoring

pub mod classifier;
pub mod fingerprint;
pub mod ngram;
pub mod similarity;

pub use classifier::{AttackClassifier, AttackPrediction, ClassifierConfig};
pub use fingerprint::{AnomalyResult, FingerprintBaseline, RequestFingerprint};
pub use ngram::CharNGramTokenizer;
pub use similarity::{PayloadSimilarity, SimilarityConfig};
