#!/bin/sh
# Prints what a disk image holds, one line per entry in path order: the mode
# and SHA-256 of each file, the target of each link, and each directory.
#
#   tools/release-darwin/dmg-contents.sh enbu-desktop_vX.Y.Z_darwin_arm64.dmg
#
# A disk image records when its file system was made and a random volume ID,
# so two builds of the same app never give the same .dmg bytes. What it holds
# does come out the same, and that is what the release compares. Left out are
# only the entries macOS writes for the volume itself (.fseventsd, .Trashes,
# the HFS+ private directories) and .DS_Store, whose Finder window layout
# points at the volume by its creation date. None of them is run.
set -eu
dmg=$1
mnt=$(mktemp -d)
hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$mnt" "$dmg" >/dev/null
trap 'hdiutil detach "$mnt" -quiet || hdiutil detach "$mnt" -force -quiet' EXIT
cd "$mnt"
find . -mindepth 1 \
  \( -name .fseventsd -o -name .Trashes -o -name '.HFS+ Private Directory Data*' -o -name '.HFS+ Private Directory Data' -o -name .journal -o -name .journal_info_block -o -name .DS_Store \) -prune \
  -o -print |
  LC_ALL=C sort |
  while IFS= read -r p; do
    if [ -L "$p" ]; then
      printf 'link %s -> %s\n' "$p" "$(readlink "$p")"
    elif [ -d "$p" ]; then
      printf 'dir %s %s\n' "$(stat -f %Lp "$p")" "$p"
    else
      printf 'file %s %s %s\n' "$(stat -f %Lp "$p")" "$(shasum -a 256 < "$p" | cut -d' ' -f1)" "$p"
    fi
  done
