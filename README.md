
static-pie-x86-64-elf-loader
============================

`cargo build && cd test && ./build_test.sh && ./test YourName`

PT\_GNU\_STACK segment is ignored, therefore it doesn't support (on purpose) ELFs with executable stack, like in [this](https://github.com/lvndry/elf-loader/blob/master/src/elf-loader.c) (non-working) project.

TODOs
-----

*   exploit SIGSEGV signal to load pages of segments on demand. see [this repo](https://github.com/anaglodariu/ELFExecutableLoader)
*   turn it into a crypter! see [this](https://0x00sec.org/t/a-simple-linux-crypter/537)
*   ask [@h0mbre](https://github.com/h0mbre) where he's gotten those [specs](https://h0mbre.github.io/New_Fuzzer_Project/#executing-the-loaded-program) about \_start rdx initialization, even though it matches with this [source](https://github.com/malisal/loaders/blob/master/elf/sysdep/linux/x86_64/arch.h) but it doesn't with [these](http://6.s081.scripts.mit.edu/sp18/x86-64-architecture-guide.html) [ones](https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/baselib---libc-start-main-.html) about args positionings
*   wait for [this](https://github.com/darfink/region-rs/issues/28) in order to get rid of flags\_to\_prot function, and [this](https://github.com/darfink/region-rs/issues/29)
*   make it work on ARM64 too!
*   modularize it
*   learn how to build macros

references
----------

*   the main reference is this [amazing series](https://fasterthanli.me/series/making-our-own-executable-packer/)
*   [this one](https://sivachandra.github.io/elf-by-example/relocations.html) tells us which types of relocation need to be applied for static(-pie) ELF
*   light [ref](http://phrack.org/issues/58/5.html) about ELF
*   about [bss](https://stackoverflow.com/questions/610682/do-bss-section-zero-initialized-variables-occupy-space-in-elf-file) section
*   the only (half) working similar (yet cryptic) [project](https://github.com/MikhailProg/elf) I found: although I edited it to make it dependent on standard libs, it calls the [\_\_libc\_start\_main fini handler](https://ftp.math.utah.edu/u/ma/hohn/linux/misc/elf/node3.html) after returning from scanf function call...

doubts to clear
---------------

*   [Amos](https://fasterthanli.me/series/making-our-own-executable-packer/part-12) and [this article](https://sivachandra.github.io/elf-by-example/crt.html) say you should setup TLS, but from the answers of [these](https://stackoverflow.com/questions/30377020/on-linux-is-tls-set-up-by-the-kernel-or-by-libc-or-other-language-runtime) [two](https://stackoverflow.com/questions/4126184/elf-file-tls-and-load-program-sections) stackoverflow questions, it seems it's not loader's duty
