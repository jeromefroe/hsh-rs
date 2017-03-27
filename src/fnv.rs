// MIT License

// Copyright (c) 2017 Jerome Froelich

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! FNV is a 64 bit implementation of the
//! [Fowler–Noll–Vo hash algorthim](http://isthe.com/chongo/tech/comp/fnv/),
//! specifically the
//! [FNV-1a alternate algorithm](http://isthe.com/chongo/tech/comp/fnv/#FNV-1a).
//!
//! FNV is a non-cryptographic hash function that is designed to be fast
//! while maintaining a low collision rate. FNV is best for applications
//! that need to hash short keys and cannot be exposed to malicious input.
//! As noted in
//! [Performance of the most common non-cryptographic hashfunctions](http://dl.acm.org/citation.cfm?id=2904542)
//! however, it does not have as good of an avalance effect as newer non-cryptographic hash functions
//! and it shows biases when used in hashmaps whose sizes are not prime.
//!
//! ## Example
//!
//! ``` rust,no_run
//! extern crate hsh;
//!
//! use std::hash::Hasher;
//! use hsh::Fnv;
//!
//! fn main() {
//!   let mut fnv = Fnv::new();
//!   fnv.write(b"foo");
//!   let hash = fnv.finish();
//!
//!   println!("The fnv hash of 'foo' is {}", hash);
//! }
//! ```

use std::hash::Hasher;

const PRIME: u64 = 1099511628211;
const OFFSET_BASIS: u64 = 14695981039346656037;

/// An implementation of the Fowler–Noll–Vo hash function, specifically
/// the FNV-1a alternative algorithim.
#[allow(missing_copy_implementations)]
pub struct Fnv(u64);

impl Fnv {
    /// Create a new FNV Hasher with the default initial state.
    pub fn new() -> Self {
        Fnv(OFFSET_BASIS)
    }

    /// Create a new FNV Hasher whose inital state is `key`.
    pub fn new_with_key(key: u64) -> Fnv {
        Fnv(key)
    }
}

impl Default for Fnv {
    /// Create a default FNV Hasher.
    fn default() -> Fnv {
        Fnv::new()
    }
}

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes.iter() {
            self.0 = self.0 ^ (*byte as u64);
            self.0 = self.0.wrapping_mul(PRIME);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;
    use super::Fnv;

    fn fnv1a(bytes: &[u8]) -> u64 {
        let mut hasher = Fnv::new();
        hasher.write(bytes);
        hasher.finish()
    }

    #[test]
    fn basic_tests() {
        assert_eq!(fnv1a(b"foo"), 15902901984413996407);
        assert_eq!(fnv1a(b"bar"), 16101355973854746);
        assert_eq!(fnv1a(b"baz"), 16092559880829058);
    }
}