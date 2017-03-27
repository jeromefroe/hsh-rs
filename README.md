# hsh

A crate implementing a variety of hash functons.

## Fowler–Noll–Vo

FNV is a 64 bit implementation of the
[Fowler–Noll–Vo hash algorthim](http://isthe.com/chongo/tech/comp/fnv/),
specifically the
[FNV-1a alternate algorithm](http://isthe.com/chongo/tech/comp/fnv/#FNV-1a).

FNV is a non-cryptographic hash function that is designed to be fast
while maintaining a low collision rate. FNV is best for applications
that need to hash short keys and cannot be exposed to malicious input.
As noted in
[Performance of the most common non-cryptographic hashfunctions](http://dl.acm.org/citation.cfm?id=2904542)
however, it does not have as good of an avalance effect as newer non-cryptographic hash functions
and it shows biases when used in hashmaps whose sizes are not prime.

### Example

``` rust
extern crate hsh;

use std::hash::Hasher;
use hsh::fnv::FnvHasher;

fn main() {
  let mut fnv = FnvHasher::new();
  fnv.write(b"foo");
  let hash = fnv.finish();

  println!("The fnv hash of 'foo' is {}", hash);
}
```

## Murmur3

murmurhash3_x86_32 is an implementation of the
[Murmur3 hash function](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp),
specifically the 32-bit version which is optimized for x86 architecture.
As noted in the reference implementation, you can compile and run the
function on any platform, but your performance with the non-native
version is less than optimal.

Murmur3 is one of the more popular non-cryptographic hash functions.
[Performance of the most common non-cryptographic hashfunctions](http://dl.acm.org/citation.cfm?id=2904542)
notes that it has a good avalanche effect, is robust enough for use
in hashmaps with sizes that are not multiples of primes, and is very
fast. Some newer hash functions have been shown to have slightly better
throughput though, for example see
[these benchmarks](https://lonewolfer.wordpress.com/2015/01/05/benchmarking-hash-functions/).

### Example

``` rust,no_run
extern crate hsh;
use hsh::murmurhash3_x86_32;
fn main() {
  let hash = murmurhash3_x86_32(42, b"foo");

  println!("The hash of 'foo' is {}", hash);
}
```
