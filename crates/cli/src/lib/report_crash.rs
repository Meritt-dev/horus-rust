//! HOR-439: the error-message surface of the bug/gap report path. Port of
//! `packages/cli/src/lib/report-crash.ts`. Prints the original error FIRST, then a dim nudge
//! towards `horus report` (kept separate from `horus feedback`).

use crate::lib::format::dim;

pub fn report_crash(err: &anyhow::Error) {
    eprintln!("{err:#}");
    eprintln!("{}", dim("\n  Looks like a Horus bug or a missing capability? Report it:  horus report"));
}
