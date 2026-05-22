//! Audit log with tamper-evident BLAKE3 hashing.
//! Each entry is linked to the previous via its hash.

use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub decision: String,
    pub previous_hash: String,
    pub hash: String,
}

pub struct AuditLog {
    chain: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        let genesis_hash = Self::hash_entry(0, &Utc::now(), "SYSTEM", "GENESIS", "INIT", "");
        let genesis = AuditEntry {
            id: 0,
            timestamp: Utc::now(),
            actor: "SYSTEM".into(),
            action: "GENESIS".into(),
            decision: "INIT".into(),
            previous_hash: "0".repeat(64),
            hash: genesis_hash,
        };
        Self { chain: vec![genesis] }
    }

    fn hash_entry(
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

    pub fn log_event(
        &mut self,
        actor: &str,
        action: &str,
        decision: &str,
    ) -> Result<&AuditEntry, &'static str> {
        let prev = self.chain.last().ok_or("Empty chain")?;
        let id = prev.id + 1;
        let ts = Utc::now();
        let hash = Self::hash_entry(id, &ts, actor, action, decision, &prev.hash);
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

    pub fn verify_integrity(&self) -> bool {
        for i in 1..self.chain.len() {
            let curr = &self.chain[i];
            let prev = &self.chain[i - 1];
            let recomputed = Self::hash_entry(
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
}
