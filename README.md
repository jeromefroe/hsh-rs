# hsh

A crate implementing a variety of hash functons.

## Fowler–Noll–Vo

A 64 bit implementation of the [Fowler–Noll–Vo hash algorthim](http://isthe.com/chongo/tech/comp/fnv/),
specifically the [FNV-1a alternate algorithm](http://isthe.com/chongo/tech/comp/fnv/#FNV-1a) is
provided by the `fnv` submodule. FNV is a non-cryptographic hash function that is designed
to be fast while maintaining a low collision rate. FNV is best for applications that need
to hash short keys and cannot be exposed to malicious input. As noted in
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