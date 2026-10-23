//! Output helpers that never panic on a write error.
//!
//! `println!` panics when the write fails, so `mcp-ctl list | head -1` died with
//! "failed printing to stdout: Broken pipe" and `mcp-ctl up | whatever` would take
//! the whole hub down when the consumer of its log output went away. These macros
//! drop the error instead: short commands exit quietly, and a running service keeps
//! serving even when nobody is reading its output anymore.

/// Print a line to stdout, ignoring write errors.
macro_rules! outln {
    () => {{
        use ::std::io::Write;
        let _ = writeln!(::std::io::stdout());
    }};
    ($($arg:tt)*) => {{
        use ::std::io::Write;
        let _ = writeln!(::std::io::stdout(), $($arg)*);
    }};
}

/// Print a line to stderr, ignoring write errors.
macro_rules! errln {
    () => {{
        use ::std::io::Write;
        let _ = writeln!(::std::io::stderr());
    }};
    ($($arg:tt)*) => {{
        use ::std::io::Write;
        let _ = writeln!(::std::io::stderr(), $($arg)*);
    }};
}
