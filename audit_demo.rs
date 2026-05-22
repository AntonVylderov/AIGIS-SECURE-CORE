//! Demonstration of the audit log functionality.

use aigis_core::audit_log::AuditLog;

fn main() {
    let mut log = AuditLog::new();
    log.log_event("system", "START", "OK").unwrap();
    log.log_event("alice", "LOGIN", "ALLOW").unwrap();
    log.log_event("z3_engine", "VERIFY", "PASS").unwrap();

    println!("Audit log integrity: {}", log.verify_integrity());
    for entry in log.iter() {
        println!(
            "[{}] {}: {} -> {}",
            entry.id, entry.actor, entry.action, entry.decision
        );
    }
}
