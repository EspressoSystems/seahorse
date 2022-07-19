// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, Write};

#[derive(Clone, Debug, Default)]
pub struct MatchResult(HashMap<String, String>);

impl MatchResult {
    pub fn insert(&mut self, capture: String, value: String) {
        self.0.insert(capture, value);
    }

    pub fn get(&self, capture: &str) -> String {
        self.0.get(capture).unwrap().clone()
    }
}

/// Read output from a given output stream until hitting a prompt (">"). Each regex in
/// `patterns` must match at least one line of output (but not necessarily in order, and not all
/// of the output must match a pattern). The patterns are matched against sub-strings of each
/// output line, so to match an entire line use `^(pattern)$`.
///
/// Named patterns (`(?P<name>pattern)`) in the regexes are added to a MatchResult dictionary,
/// which is returned at the end of the operation.
pub fn match_output(output: &mut impl BufRead, patterns: &[impl AsRef<str>]) -> MatchResult {
    // Read output until we get a prompt or EOF.
    let mut lines = vec![];
    let mut line = String::new();
    while let Ok(n) = output.read_line(&mut line) {
        if n == 0 || line.trim() == ">" {
            break;
        }
        // println!("output: {}", line);
        lines.push(std::mem::take(&mut line));
    }

    // Try matching each pattern against an output line. Panic if any pattern doesn't match.
    let mut matches = MatchResult::default();
    'pattern: for pattern in patterns {
        let regex = Regex::new(pattern.as_ref()).unwrap();
        for line in &lines {
            if let Some(re_match) = regex.captures(line.trim()) {
                for capture in regex.capture_names().flatten() {
                    if let Some(capture_match) = re_match.name(capture) {
                        matches.insert(String::from(capture), String::from(capture_match.as_str()));
                    }
                }
                continue 'pattern;
            }
        }

        panic!(
            "Pattern `{}' did not match output:\n{}",
            regex,
            lines.join("")
        );
    }

    matches
}

pub fn wait_for_prompt(output: &mut impl BufRead) {
    match_output(output, &Vec::<&str>::new());
}

// A version of `testing::await_transaction` that uses the CLI.
pub fn await_transaction(
    receipt: &str,
    sender: (&mut impl Write, &mut impl BufRead),
    receivers: &mut [(&mut impl Write, &mut impl BufRead)],
) {
    // Wait for the sender to verify the transaction is complete, and get the index of an event
    // equal to or later than the last event related to this transaction.
    writeln!(sender.0, "wait {}", receipt).unwrap();
    wait_for_prompt(sender.1);
    writeln!(sender.0, "now").unwrap();
    let matches = match_output(sender.1, &["(?P<t>.*)"]);
    let t = matches.get("t");

    // Wait for each receiver to process up to the last relevant event.
    for receiver in receivers.iter_mut() {
        writeln!(receiver.0, "sync {}", t).unwrap();
    }
    for receiver in receivers.iter_mut() {
        wait_for_prompt(receiver.1);
    }
}
