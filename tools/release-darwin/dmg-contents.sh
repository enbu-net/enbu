#!/bin/sh
# Prints what a disk image holds, one line per entry in path order: the mode
# and SHA-256 of each file, the target of each link, and each directory.
#
#   tools/release-darwin/dmg-contents.sh enbu-desktop_vX.Y.Z_darwin_arm64.dmg
#
# A disk image records when its file system was made and a random volume ID,
# so two builds of the same app never give the same .dmg bytes. What it holds
# does come out the same, and that is what the release compares. Left out are
# only these entries at the root of the volume, which macOS writes for the
# volume itself: .fseventsd, .Trashes, the HFS+ private directories and journal
# files, and .DS_Store, whose Finder window layout points at the volume by its
# creation date. None of them is run; everything inside the app is listed.
set -eu
dmg=$1
mnt=$(mktemp -d)
hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$mnt" "$dmg" >/dev/null
trap 'hdiutil detach "$mnt" -quiet || hdiutil detach "$mnt" -force -quiet' EXIT
cd "$mnt"
# Plain assignments and redirections, never a pipe, so that set -e stops the
# script on any failure instead of printing a short list.
tmp=$(mktemp -d)
find . -mindepth 1 \
  \( -path ./.fseventsd -o -path ./.Trashes -o -path './.HFS+ Private Directory Data*' -o -path ./.journal -o -path ./.journal_info_block -o -path ./.DS_Store \) -prune \
  -o -print > "$tmp/found"
LC_ALL=C sort "$tmp/found" > "$tmp/sorted"
test -s "$tmp/sorted"
while IFS= read -r p; do
  if [ -L "$p" ]; then
    target=$(readlink "$p")
    printf 'link %s -> %s\n' "$p" "$target"
  elif [ -d "$p" ]; then
    mode=$(stat -f %Lp "$p")
    printf 'dir %s %s\n' "$mode" "$p"
  else
    mode=$(stat -f %Lp "$p")
    sum=$(shasum -a 256 < "$p")
    printf 'file %s %s %s\n' "$mode" "${sum%% *}" "$p"
  fi
done < "$tmp/sorted"
rm -rf "$tmp"
