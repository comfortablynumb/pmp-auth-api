// Session management module
// Provides active session tracking, concurrent session limits, and activity monitoring

#![allow(dead_code)]

pub mod manager;
pub mod storage;
pub mod types;

pub use manager::{SessionManager, SessionManagerState};
pub use storage::{MemorySessionStorage, SessionStorage};
pub use types::{
    Session, SessionActivity, SessionConfig, SessionInfo, SessionQuery, SessionStatus,
};
