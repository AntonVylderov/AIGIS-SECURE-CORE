//! Tamper‑evident audit log with BLAKE3 hashing.
//! Each entry is cryptographically linked to the previous one.

use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub decision: String,
    pub previous_hash: String,
    pub hash: String,
}

/// Audit log – a blockchain‑like append‑only structure.
pub struct AuditLog {
    chain: Vec<AuditEntry>,
}

impl AuditLog {
    /// Creates a new audit log with a genesis entry.
    pub fn new() -> Self {
        let genesis = AuditEntry {
            id: 0,
            timestamp: Utc::now(),
            actor: "SYSTEM".into(),
            action: "GENESIS".into(),
            decision: "INIT".into(),
            previous_hash: "0".repeat(64),
            hash: Self::compute_hash(0, &Utc::now(), "SYSTEM", "GENESIS", "INIT", ""),
        };
        Self { chain: vec![genesis] }
    }

    fn compute_hash(
        id: u64,
        ts: &DateTime<Utc>,
        actor: &str,
        action: &str,
        decision: &str,
        prev_hash: &str,
    ) -> String {
        let payload = format!("{}{}{}{}{}{}", id, ts, actor, action, decision, prev_hash);
        let mut hasher = Hasher::new();
        hasher.update(payload.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Appends a new event to the log.
    pub fn log_event(
        &mut self,
        actor: &str,
        action: &str,
        decision: &str,
    ) -> Result<&AuditEntry, &'static str> {
        let prev = self.chain.last().ok_or("Empty chain")?;
        let id = prev.id + 1;
        let ts = Utc::now();
        let hash = Self::compute_hash(id, &ts, actor, action, decision, &prev.hash);
        let entry = AuditEntry {
            id,
            timestamp: ts,
            actor: actor.into(),
            action: action.into(),
            decision: decision.into(),
            previous_hash: prev.hash.clone(),
            hash,
        };
        self.chain.push(entry);
        Ok(entry)
    }

    /// Verifies the integrity of the whole chain.
    pub fn verify_integrity(&self) -> bool {
        for i in 1..self.chain.len() {
            let curr = &self.chain[i];
            let prev = &self.chain[i - 1];
            let recomputed = Self::compute_hash(
                curr.id,
                &curr.timestamp,
                &curr.actor,
                &curr.action,
                &curr.decision,
                &prev.hash,
            );
            if recomputed != curr.hash || curr.previous_hash != prev.hash {
                return false;
            }
        }
        true
    }

    /// Returns an iterator over the entries.
    pub fn iter(&self) -> std::slice::Iter<AuditEntry> {
        self.chain.iter()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_verify() {
        let mut log = AuditLog::new();
        log.log_event("alice", "LOGIN", "ALLOW").unwrap();
        log.log_event("bob", "TRANSFER", "BLOCK").unwrap();
        assert!(log.verify_integrity());
        assert_eq!(log.iter().count(), 3); // genesis + 2
    }

    #[test]
    fn test_tampered_hash_detected() {
        let mut log = AuditLog::new();
        log.log_event("alice", "LOGIN", "ALLOW").unwrap();
        // Simulate tampering
        let mut entry = log.chain.last_mut().unwrap();
        entry.hash = "tampered".to_string();
        assert!(!log.verify_integrity());
    }
}
