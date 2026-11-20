use std::sync::{Mutex, MutexGuard};

mod advert;
mod engine;
pub mod nullifiers;

pub use advert::served_pairs;
pub use engine::{
    Configured, Denial, Engine, ExecError, Refusal, ServeState, Service, Spend,
    DEFAULT_CONFIRM_BUDGET_S,
};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
