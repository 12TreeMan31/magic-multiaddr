# magic-multiaddr
A no_std implmentation of multiformats multiaddr

This library is still a work in progress, and I only work on it when I have time away from school. For the most part though, the public api should(?) stay the same Currently, you should be able to do almost anything you would need from the format (although not in the most efficent way). 

## Usage
The purpose of this libaray is to act like glue for any codec table you wish to implement. As such, this library only handles converting between binary and text representions, not the logic for parsing a protocol. If you are looking for something like that, I have written a example of how to implement your own codec in `lib.rs` under the test module.

