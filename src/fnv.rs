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

//! A 64 bit implementation of the [Fowler–Noll–Vo hash algorthim](http://isthe.com/chongo/tech/comp/fnv/),
//! specifically the [FNV-1a alternate algorithm](http://isthe.com/chongo/tech/comp/fnv/#FNV-1a)
//!
//! FNV is a non-cryptographic hash function that is designed to be fast while
//! maintaining a low collision rate. FNV is best for applications that need
//! to hash short keys and cannot be exposed to malicious input.
//!
//! ## Example
//!
//! ``` rust,no_run
//! extern crate hsh;
//!
//! use std::hash::Hasher;
//! use hsh::fnv::FnvHasher;
//!
//! fn main() {
//! let mut fnv = FnvHasher::new();
//! fnv.write(b"foo");
//! let hash = fnv.finish();
//!
//! println!("The fnv hash of 'foo' is {}", hash);
//! }
//! ```

use std::hash::Hasher;

const PRIME: u64 = 1099511628211;
const OFFSET_BASIS: u64 = 14695981039346656037;

/// An implementation of the Fowler–Noll–Vo hash function, specifically
/// the FNV-1a alternative algorithim.
#[allow(missing_copy_implementations)]
pub struct FnvHasher {
    hash: u64,
}

impl FnvHasher {
    /// Create a new FNV Hasher with the default initial state..
    pub fn new() -> Self {
        FnvHasher { hash: OFFSET_BASIS }
    }

    /// Create a new FNV Hasher whose inital state is `key`.
    pub fn new_with_key(key: u64) -> FnvHasher {
        FnvHasher { hash: key }
    }
}

impl Default for FnvHasher {
    /// Create a default FNV Hasher.
    fn default() -> FnvHasher {
        FnvHasher::new()
    }
}

impl Hasher for FnvHasher {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes.iter() {
            self.hash = self.hash ^ (*byte as u64);
            self.hash = self.hash.wrapping_mul(PRIME);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;
    use super::FnvHasher;

    fn fnv1a(bytes: &[u8]) -> u64 {
        let mut hasher = FnvHasher::new();
        hasher.write(bytes);
        hasher.finish()
    }

    #[test]
    fn basic_tests() {
        assert_eq!(fnv1a(b"foo"), 015902901984413996407);
        assert_eq!(fnv1a(b"bar"), 16101355973854746);
        assert_eq!(fnv1a(b"baz"), 16092559880829058);
    }
}