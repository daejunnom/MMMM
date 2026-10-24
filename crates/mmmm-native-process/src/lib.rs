//! Native process observations shared by the Coordinator and build supervisor.
//!
//! This crate does not establish process ownership, choose resource budgets,
//! install a policy, signal a process, or certify that an owned scope drained.
//! Each consumer retains its own identity checks and original deadline.

pub mod darwin;
