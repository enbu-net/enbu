#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: $0 OUTPUT.wasm" >&2
	exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output=$1
case "$output" in
	/*) ;;
	*) output="$repo_root/$output" ;;
esac

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

copy_and_patch() {
	module=$1
	target_name=$2
	patch_file=$3

	module_dir=$(go list -m -f '{{.Dir}}' "$module")
	target_dir="$work_dir/$target_name"
	cp -R "$module_dir" "$target_dir"
	chmod -R u+w "$target_dir"
	patch --batch --forward -d "$target_dir" -p1 < "$repo_root/test/preview/patches/$patch_file"
	go mod edit -modfile="$work_dir/enbu-preview.mod" -replace="$module=$target_dir"
}

cp "$repo_root/go.mod" "$work_dir/enbu-preview.mod"
cp "$repo_root/go.sum" "$work_dir/enbu-preview.sum"

# Remove the Bubble Tea patch once https://github.com/charmbracelet/bubbletea/pull/1767 lands.
copy_and_patch "charm.land/bubbletea/v2" "bubbletea" "bubbletea-wasip1.patch"
copy_and_patch "github.com/atotto/clipboard" "atotto-clipboard" "atotto-clipboard-wasip1.patch"

mkdir -p "$(dirname -- "$output")"

go_debug=goindex=0
if [ -n "${GODEBUG:-}" ]; then
	go_debug="$GODEBUG,$go_debug"
fi

cd "$repo_root"
GODEBUG="$go_debug" GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 \
	go build \
	-modfile="$work_dir/enbu-preview.mod" \
	-trimpath \
	-buildvcs=false \
	-ldflags="-s -w" \
	-o "$output" \
	./test/preview/tui-demo
