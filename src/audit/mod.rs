// Audit logging system for compliance and security tracking
// Provides comprehensive audit trail for all authentication and admin operations

#![allow(dead_code)]

pub mod logger;
pub mod storage;
pub mod types;

pub use logger::{AuditLogger, AuditLoggerState};
pub use storage::{AuditStorage, MemoryAuditStorage, PostgresAuditStorage};
pub use types::{AuditAction, AuditEntry, AuditLevel, AuditQuery, ComplianceReport, ResourceType};
