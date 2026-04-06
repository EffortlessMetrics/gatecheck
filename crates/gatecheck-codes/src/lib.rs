//! Stable exit codes for gatecheck.

/// Stable process exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Successful completion.
    Success = 0,
    /// Invalid usage or missing arguments.
    Usage = 2,
    /// A file or parse error occurred.
    InputError = 3,
    /// A gate report was emitted and contains a blocker.
    GateBlocked = 4,
    /// Internal error.
    InternalError = 70,
}

impl ExitCode {
    /// Convert to a process-compatible `i32`.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }
}
