// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! I/O interface for the CLI.
//!
//! Having an interface for I/O which can be implemented with any underlying I/O primitive makes it
//! easy to swap out the actual I/O implementation used by the CLI for testing and automation
//! purposes.
use async_std::task::spawn_blocking;
use pipe::{pipe, PipeReader, PipeWriter};
use std::io;
use std::io::{stdin, stdout, BufRead, Read, Write};
use std::sync::{Arc, Mutex};

/// Wrapper around an input stream and an output stream
///
/// Both the input and output are trait objects, so any types implementing [Read] and [Write] can be
/// used here.
///
/// [SharedIO] also has an internal buffer so that it can implement [BufRead].
#[derive(Clone)]
pub struct SharedIO {
    input: Arc<Mutex<dyn Read + Send>>,
    output: Arc<Mutex<dyn Write + Send>>,
    buf: Vec<u8>,
}

impl SharedIO {
    /// Construct a new I/O object with particular [Read] and [Write] implementations.
    pub fn new(input: impl Read + Send + 'static, output: impl Write + Send + 'static) -> Self {
        Self {
            input: Arc::new(Mutex::new(input)),
            output: Arc::new(Mutex::new(output)),
            buf: Vec::new(),
        }
    }

    /// Create a [SharedIO] instance using a bidirectional pipe.
    ///
    /// Returns an IO instance, plus a pair of pipe ends to communicate with the SharedIO. The
    /// [PipeWriter] can be used to send input to the [SharedIO], and the [PipeReader] to read its
    /// output.
    pub fn pipe() -> (Self, PipeWriter, PipeReader) {
        let (read_input, write_input) = pipe();
        let (read_output, write_output) = pipe();
        (
            Self::new(read_input, write_output),
            write_input,
            read_output,
        )
    }

    /// Create a [SharedIO] instance that uses the standard I/O streams [stdin] and [stdout].
    pub fn std() -> Self {
        Self::new(stdin(), stdout())
    }
}

impl Read for SharedIO {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // `read` can be implemented in terms of `fill_buf` and `consume` from the `BufRead`
        // instance, which ensures the two implementations will be consistent.
        let data = self.fill_buf()?;
        let size = std::cmp::min(data.len(), buf.len());
        buf[..size].copy_from_slice(&data[..size]);
        self.consume(size);
        Ok(size)
    }
}

impl BufRead for SharedIO {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.buf.is_empty() {
            // We have to give the underlying read method a non-empty buffer, because `read` will
            // only return data up to the length of the buffer it is given. Fill our buffer with
            // zeros, arbitrarily hoping to read 128 bytes. If we read less, we will truncate the
            // buffer.
            self.buf.resize(128, 0u8);
            let size = self.input.lock().unwrap().read(&mut self.buf)?;
            // Resize buf to the amount of data we actually read. Note that `size` is allowed to be
            // 0 in the case of EOF, in which case we will return an empty buffer, also indicating
            // EOF.
            assert!(size <= 128);
            self.buf.resize(size, 0u8);
        }
        Ok(&self.buf)
    }

    fn consume(&mut self, amt: usize) {
        assert!(amt <= self.buf.len());
        self.buf.drain(..amt);
    }
}

impl Write for SharedIO {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.lock().unwrap().flush()
    }
}

/// Adapter for an input or output stream which echoes all I/O passing through the stream to stdout.
#[derive(Clone, Debug)]
pub struct Tee<S> {
    stream: S,
}

impl<S> Tee<S> {
    #[cfg(any(test, feature = "testing"))]
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<W: Write> Write for Tee<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.stream.write(buf)?;
        stdout().write_all(&buf[..n]).unwrap();
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()?;
        stdout().flush().unwrap();
        Ok(())
    }
}

impl<R: Read> Read for Tee<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.stream.read(buf)?;
        stdout().write_all(&buf[..n]).unwrap();
        Ok(n)
    }
}

impl<R: BufRead> BufRead for Tee<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.stream.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        stdout()
            .write_all(&self.fill_buf().unwrap()[..amt])
            .unwrap();
        self.stream.consume(amt);
    }
}

#[macro_export]
macro_rules! async_writeln {
    ($io:expr, $fmt:expr, $($arg:expr),* $(,)?) => {
        {
            let args = format_args!($fmt, $($arg),*).to_string();
            let mut io = $io.clone();
            async_std::task::spawn_blocking(move || { writeln!(io, "{}", args).unwrap() }).await
        }
    };
    ($io:expr$(, $fmt:expr)?) => {
        {
            let mut io = $io.clone();
            async_std::task::spawn_blocking(move || { writeln!(io, $($fmt)?).unwrap() }).await
        }
    };
}

#[macro_export]
macro_rules! async_write {
    ($io:expr, $fmt:expr, $($arg:expr),* $(,)?) => {
        {
            let args = format_args!($fmt, $($arg),*).to_string();
            let mut io = $io.clone();
            async_std::task::spawn_blocking(move || { write!(io, "{}", args).unwrap() }).await
        }
    };
    ($io:expr$(, $fmt:expr)?) => {
        {
            let mut io = $io.clone();
            async_std::task::spawn_blocking(move || { write!(io, $($fmt)?).unwrap() }).await
        }
    };
}

pub async fn async_read_line(
    output: &(impl Clone + BufRead + Send + 'static),
    line: &mut String,
) -> io::Result<usize> {
    let mut output = output.clone();
    let (res, buf) = spawn_blocking(move || {
        let mut buf = String::new();
        let res = output.read_line(&mut buf);
        (res, buf)
    })
    .await;
    *line = buf;
    res
}
