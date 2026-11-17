# Vendor provenance — libhydrogen

- **Upstream:** `https://github.com/jedisct1/libhydrogen`
- **Pinned commit:** `6c58976b3b9178441218c12bca2cc414d9efe30d`
- **Fetch URL template:** `https://raw.githubusercontent.com/jedisct1/libhydrogen/6c58976b3b9178441218c12bca2cc414d9efe30d/<path>`
- **Pinned by:** the `angt/secret` tree `3583d25dd6941c15e6606b2063ca84e37ecbc6ea` (`.gitmodules` pins libhydrogen to this exact commit).

Files are vendored verbatim; no modifications were made to any C source or header.

## sha256 of vendored files

| File | sha256 |
|---|---|
| `hydrogen.c` | `b0472cb9aa632ecc59d78ffe0ef07b1c20b751f5600de0f1dadc733ec0f1648b` |
| `hydrogen.h` | `ee14f2df8c784d0f2af5f7af1aa4a1f5cbde684a35da8b80638aadead5c76aca` |
| `LICENSE` | `f42c6163865ccd11af88461205bc325a38ff89548465ef6ed8ad9fbee7703596` |
| `README.md` | `66b60c5e9ae3454c419f5057c3aeeacaceb470b45e40bcf69b3b3e52ff25f3c3` |
| `impl/common.h` | `fff885f51e8266b612c0b143d81e2e857c02fea9a76255a182a3b1633d386cea` |
| `impl/core.h` | `8cd43858b10e04594302f8ddaa164110e0af0daa7db0a852237a10926e1a8b29` |
| `impl/gimli-core.h` | `c1b85957f4ad21829b4e00c44e57d1a77acf581a2975674b32090a146fae3986` |
| `impl/gimli-core/portable.h` | `b39ce98ad6ee23c07acdc945fc22ae5167af722ffdcea077d438a1e8c7ef894f` |
| `impl/gimli-core/sse2.h` | `9edadc3fcacbc073a963861992c4ec7e9752a7459aaeac15a86ce89edc4a8774` |
| `impl/hash.h` | `a62ebe43c25d2b009f6e716e0e0c8bd8bcdd8213c907e83aa8e11e28fd4af0e7` |
| `impl/hydrogen_p.h` | `bdb8c5dd82c28104c376fa39cc5ee63a7385c31d4213235ad2633ac8726b259d` |
| `impl/kdf.h` | `1781d5ff2e7081e9382045f436f2d2c3a79529f14af037ed1440f25017ae0d36` |
| `impl/kx.h` | `e98ce20c5da59f01173c5322e078e12460d46da70bfa203be94a0fb7fe138d0b` |
| `impl/pwhash.h` | `1ffaa93bcf6e85bbd328c1a3fdce8e415d7591c4d29d0b3d3f550f00bbab3a64` |
| `impl/random.h` | `f6309eee22f6193c0f4ff608d5a3658f71fe82161e52709f2b7e987b1f2c7550` |
| `impl/random/avr.h` | `f2e4b734a4c2c5ac9c297a69b96bbbe583fbb69cb17c37d57520d66af9c40723` |
| `impl/random/ch32.h` | `b37c32818647a0d9a6e2acaf47c5c3cc053a4ca22358ec1df42cf49af7ad72f6` |
| `impl/random/cheriot.h` | `9cab172cf408786a98877248defc8b68a412df24b0581be608bd47fece3d5145` |
| `impl/random/chibios.h` | `0e4f1c1fdd57c8b876b3ee6c7ba497974c59c624fd758736d22ff2be4c051016` |
| `impl/random/esp32.h` | `79fbf2a6b826bc030991958b5e28924fa3b30f6ad86070300976fb25a0f8c94f` |
| `impl/random/linux_kernel.h` | `afde224142b345986ce0576f6f5105cc93bb52e92e3db2a48b6e190afed331d2` |
| `impl/random/mbed.h` | `d57893f51468c4f349d0e7c8a0ef8f7151565ab96bd9335b0dbbabb7e4bbad23` |
| `impl/random/nrf52832.h` | `521d27104a46807118602e9f05b01c291d8c00598e6ba171f4a0a26582655fba` |
| `impl/random/particle.h` | `fefe6d356383f3f25a31d2e68cf87cd789194b2f85e183a7a9a52e691baba55b` |
| `impl/random/riot.h` | `dcbc09a0f1ed57a3ceb487b70bc9362aee02e3e285e51488d2d8a27bc082600e` |
| `impl/random/rtthread.h` | `2d011b74d24004a89d22e4b0c0f83725aac026798104f6fc1f16f55c6b2da6b7` |
| `impl/random/stm32.h` | `1d25a22e0f18d3f57762c4e597a6d490fd502f8238adc8dba4407aa36b3cdcc2` |
| `impl/random/unix.h` | `58f0da36263deba8a365b89c1abff5d220c173a920411e16e40b0e5c97a4851b` |
| `impl/random/wasi.h` | `6d38e81c5677b7e7e65de6d6c2e82d6b235cc03ef9602498f193aa8a06fcb52d` |
| `impl/random/windows.h` | `e3153321a6415de9a9d2b8f2575f2c4c7aa2fd432255a7bc25fded5ad0fce9f2` |
| `impl/random/zephyr.h` | `b57cf92e21ba52963046424818cf5b081c55aee99d800a4e40c97c1045d860cd` |
| `impl/secretbox.h` | `9304daf29745e314ecf79ed9e9426e891937a18a5d84ee342d63fdc9b7d779c6` |
| `impl/sign.h` | `10d9642563b4ebd3a2ee4bd7f1b6eb5e19be03e01b14655501b8df264c521d0f` |
| `impl/x25519.h` | `3f0e59c22e5a4ba9e10f47a29d4600dbac3cd5fb59b6535ebc88007707df55a3` |
| `tests/tests.c` | `3adc28437d3ed82bc9cb94472c2a46eaaf6e354cf9821d0bb244f52b819b8954` |

`hydrogen.c` and `hydrogen.h` match the expected reference digests recorded in the
implementation plan. All other digests were computed from the files as fetched from the
pinned commit.

## Excluded from vendoring

The following upstream files are intentionally NOT vendored (build-system, CI,
test, and metadata only; not needed to compile `hydrogen.c`):

- `.github/`
- `cmake/`
- `tests/` — **except `tests/tests.c`, which IS vendored** (below) as the KAT
  harness source (2026-11-17). At the pinned commit upstream `tests/` contains
  `tests.c` only, so this is the complete upstream test suite. The file is kept
  verbatim (sha256 `3adc2843…b8954` above) and compiled by
  `crates/libhydrogen-sys/build.rs` into the standalone `hydrogen_tests` binary
  run by `crates/libhydrogen-sys/tests/kat.rs`.
- `tis-ci/`
- `tis.config`
- `.gitignore`
- `meson.build`
- `build.zig`, `build.zig.zon`
- `Makefile`, `Makefile.arduino`, `Makefile.chibios`, `Makefile.particle`
- `CMakeLists.txt`
- `library.properties`
- `logo.png`
- `CITATION.cff`
- `.clang-format`, `.cmake-format.json`
- `.travis.yml`

## License notice requirement

libhydrogen is licensed under the **ISC License** (see `vendor/LICENSE`):

> Copyright (c) 2017-2026 Frank Denis
>
> Permission to use, copy, modify, and/or distribute this software for any
> purpose with or without fee is hereby granted, provided that the above
> copyright notice and this permission notice appear in all copies.

The ISC license requires that the copyright notice and permission notice be
**preserved in all copies and substantial portionsions of the software**, for both
source and binary redistribution. Any distribution of `wsecret` (or
`libhydrogen-sys`) must therefore include `vendor/LICENSE` (or an equivalent
reproduction of this notice). This obligation is independent of the BSD-2-Clause
license of the `angt/secret` sources themselves.
