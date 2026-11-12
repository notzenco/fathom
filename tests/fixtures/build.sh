#!/bin/sh
# Rebuild the fixture binaries.  Needs zig (any host), plus Docker for
# the gcc-built stripped PIE and Apple's lipo for the universal binary.
set -eu
cd "$(dirname "$0")"

FLAGS="-O0 -g0 -fno-sanitize=all -fno-omit-frame-pointer"

zig cc -target x86_64-linux-gnu    $FLAGS -o elf-x86_64        fixture.c
zig cc -target aarch64-linux-gnu   $FLAGS -o elf-arm64         fixture.c
zig cc -target x86_64-macos        $FLAGS -o macho-x86_64      fixture.c
zig cc -target aarch64-macos       $FLAGS -o macho-arm64       fixture.c
zig cc -target x86_64-windows-gnu  $FLAGS -o pe-x86_64.exe     fixture.c
zig cc -target aarch64-windows-gnu $FLAGS -o pe-arm64.exe      fixture.c
rm -f ./*.pdb

# What a mainstream Linux toolchain emits: gcc, PIE, .plt.sec, stripped.
docker run --rm --platform linux/amd64 -v "$PWD":/f -w /f ubuntu:24.04 sh -c \
    'apt-get update -qq && apt-get install -y -qq gcc >/dev/null &&
     gcc -O0 -fno-omit-frame-pointer -o elf-x86_64-gcc-stripped fixture.c &&
     strip elf-x86_64-gcc-stripped'

lipo -create -output macho-universal macho-x86_64 macho-arm64
