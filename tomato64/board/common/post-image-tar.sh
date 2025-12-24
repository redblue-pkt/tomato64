#!/bin/sh
set -e
set -x

MODEL="$2"

for ext in zst gz xz bz2 lzma lzo lz4; do
    src="$BINARIES_DIR/rootfs.tar.$ext"
    if [ -f "$src" ]; then
        dst="$BINARIES_DIR/${MODEL}-update.tar.$ext"
        rm -f "$dst"
        mv "$src" "$dst"
    fi
done

found=0
for ext in zst gz xz bz2 lzma lzo lz4; do
    [ -f "$BINARIES_DIR/${MODEL}-update.tar.$ext" ] && found=1
done

if [ "$found" -eq 0 ]; then
    echo "ERROR: No rootfs.tar.<zst|gz|xz|bz2|lzma|lzo> found in $BINARIES_DIR" >&2
    exit 1
fi

