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

//! murmurhash3_x86_32 is an implementation of the
//! [Murmur3 hash function](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp),
//! specifically the 32-bit version which is optimized for x86 architecture.
//! As noted in the reference implementation, you can compile and run the
//! function on any platform, but your performance with the non-native
//! version is less than optimal.
//!
//! Murmur3 is one of the more popular non-cryptographic hash functions.
//! [Performance of the most common non-cryptographic hashfunctions](http://dl.acm.org/citation.cfm?id=2904542)
//! notes that it has a good avalanche effect, is robust enough for use in
//! hashmaps with sizes that are not multiples of primes, and is very fast.
//! Some newer hash functions have been shown to have slightly better
//! throughput though, for example see
//! [these benchmarks](https://lonewolfer.wordpress.com/2015/01/05/benchmarking-hash-functions/).
//!
//! ## Example
//!
//! ``` rust,no_run
//! extern crate hsh;
//!
//! use hsh::murmurhash3_x86_32;
//!
//! fn main() {
//!   let hash = murmurhash3_x86_32(42, b"foo");
//!
//!   println!("The hash of 'foo' is {}", hash);
//! }
//! ```

use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};

/// An implementation of the 32 bit version of the Murmur3 hash
/// function.
pub fn murmurhash3_x86_32(seed: u32, bytes: &[u8]) -> u32 {
    let nblocks = bytes.len() / 4;
    let mut reader = Cursor::new(bytes);

    let mut h1 = seed;

    let c1 = 0xcc9e2d51;
    let c2 = 0x1b873593;

    for _ in 0..nblocks {
        let mut k1 = reader.read_u32::<LittleEndian>().unwrap();
        k1 = k1.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);

        h1 ^= k1;
        h1.rotate_left(13).wrapping_mul(5).wrapping_add(0xe6546b64);
    }

    let bytes_left = bytes.len() - (nblocks * 4);

    let mut k1 = match bytes_left {
        3 => {
            let mut k1 = reader.read_u16::<LittleEndian>().unwrap() as u32;
            k1 <<= 8;
            k1 += reader.read_u8().unwrap() as u32;
            k1
        }
        2 => reader.read_u16::<LittleEndian>().unwrap() as u32,
        1 => reader.read_u8().unwrap() as u32,
        _ => {
            panic!("Invalid number of bytes left");
        }
    };

    k1 = k1.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);
    h1 ^= k1;

    h1 ^= bytes.len() as u32;
    h1 ^= h1.wrapping_shr(16);
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1.wrapping_shr(13);
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1.wrapping_shr(16);

    h1
}

#[cfg(test)]
mod tests {
    use super::murmurhash3_x86_32;

    #[test]
    fn basic_tests() {
        assert_eq!(murmurhash3_x86_32(42, b"foo"), 1490047128);
        assert_eq!(murmurhash3_x86_32(123456789, b"bar"), 2996396419);
        assert_eq!(murmurhash3_x86_32(864217, b"baz"), 174231400);
    }
}