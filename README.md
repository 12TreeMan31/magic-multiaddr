# magic-multiaddr
A no_std implmentation of multiformats multiaddr

This library is not finished, and I only work on it when I have time away from school. For the most part though, the public api should(?) stay the same.

## Usage
The purpose of this libaray is to act like glue for any codec table you wish to implment. As such, this library only handles converting between binary and text representions, not the logic for parsing a protocol. If you are looking for something like that, I have written a very good example of how to implment your own codec in `lib.rs` under the tests module.
