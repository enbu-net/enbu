# Verifying and reproducing a release

A release is only as trustworthy as the machine that built it. enbu gives you
two independent checks:

1. **Provenance**: every asset is signed with Sigstore and attested by the
   `release-build.yaml` workflow of `enbu-net/enbu`. This proves *where* an
   asset was built.
2. **Reproducibility**: the assets listed below come out bit for bit the same
   when anyone builds the release tag again. This proves *what* was built: the
   published binary is the source code of the tag and nothing else, even if the
   release workflow or its runner were compromised.

## Check a download

Check provenance with the GitHub CLI before installing:

```sh
gh attestation verify enbu_vX.Y.Z_linux_amd64.tar.gz \
  --repo enbu-net/enbu \
  --signer-workflow enbu-net/enbu/.github/workflows/release-build.yaml
```

Or with cosign, using the `.sigstore.json` bundle next to each asset:

```sh
cosign verify-blob enbu_vX.Y.Z_linux_amd64.tar.gz \
  --bundle enbu_vX.Y.Z_linux_amd64.tar.gz.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/enbu-net/enbu/\.github/workflows/release-build\.yaml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$'
```

## Reproducible assets

Every asset of a release is reproducible.

| Asset | Built on | How |
| --- | --- | --- |
| `enbu_*` archives, `.deb`, `.rpm`, `.apk`, `.pkg.tar.zst` | Linux | GoReleaser, `CGO_ENABLED=0`, `-trimpath`, file times, owners and the RPM build host fixed |
| `enbu-desktop_*_windows_*.zip` | Linux | cross-built without cgo, zipped by `tools/reproarchive` |
| `enbu-vscode_*.vsix` | Linux | `vsce package`, then rewritten by `tools/reproarchive` |
| `enbu-desktop_*_linux_*` (`.tar.gz`, `.deb`, `.rpm`) | Linux, same CPU architecture | cgo build inside the pinned image of `tools/release-linux` |
| `enbu-desktop_*_darwin_*.dmg` | macOS, same CPU architecture | cgo build with the pinned Xcode, signed ad hoc; compared by contents (below) |

Every input is pinned: Go by `go.mod`, GoReleaser, nfpm, Node.js and pnpm by
`aqua.yaml`, the frontend and extension dependencies by their lockfiles, the
Wails CLI by `tools/wails3/go.mod`, and dmgbuild by hash in
`tools/release-darwin/requirements.txt`. The Linux desktop app links GTK 4 and
WebKitGTK 6.0, so it is built in a container whose base image and Go are pinned
by digest and whose Ubuntu packages come from a fixed date of
[snapshot.ubuntu.com](https://snapshot.ubuntu.com). The macOS app is built with
the Xcode that `XCODE_VERSION` in the workflows names. Times come from the
commit (`SOURCE_DATE_EPOCH`), never from the clock.

**Disk images are compared by contents.** A `.dmg` always records when its
file system was made and a random volume ID, so two builds of the same app
never give the same bytes. `tools/release-darwin/dmg-contents.sh` mounts an
image and lists the mode and SHA-256 of every file, every link and every
directory in it; two images match when the lists match. Left out are only
these entries at the root of the volume, which macOS keeps for the volume
itself: `.fseventsd`, `.Trashes`, the HFS+ private directories and journal
files, and `.DS_Store`, the Finder window layout, which points at the volume by
its creation date. None of these is ever run. Everything inside the app, its
signature, the `Applications` link and the background are all compared.

The release workflow enforces this. For each platform, the `build` job builds
the assets that are published, and the `reproduce` job builds them again from
a fresh clone in another directory, with no Go, tool or dependency cache. The
arm64 Linux runner also rebuilds the cross-built assets the amd64 one
publishes, so those are compared across CPU architectures as well. Nothing is
signed or published unless every asset matches. A dry run of the release
workflow (Run workflow with "Dry run" checked, on any branch) does the same
builds and comparison without tagging, signing or publishing, so a change that
breaks reproducibility can be caught before a release.

## Rebuild a release yourself

On either system you need Git, Go of the version `go.mod` names,
[aqua](https://aquaproj.github.io/) for the other pinned tools (it does not
install Go), and the Vite+ CLI (`vp`) that the frontend tasks call.

On Linux (amd64 or arm64) you rebuild everything except the macOS app. You also
need Docker for the Linux desktop app, and the GTK 4 and WebKitGTK 6.0 headers
(`libgtk-4-dev libwebkitgtk-6.0-dev`), which the Wails CLI needs to build. The
Linux desktop app is built for your machine's architecture only. On macOS you
rebuild the macOS app for your Mac's architecture; you also need Xcode of the
version that `XCODE_VERSION` in `.github/workflows/release-build.yaml` names,
selected with `DEVELOPER_DIR`.

```sh
git clone https://github.com/enbu-net/enbu && cd enbu
git checkout vX.Y.Z
aqua install
task release/build VERSION=vX.Y.Z
```

Then download the release and compare, after checking the assets' signatures
as above:

```sh
gh release download vX.Y.Z --repo enbu-net/enbu --dir published
task release/verify PUBLISHED=published
```

Every asset you built must say `OK`. A mismatch means the published asset is
not what the tag's source produces: please open an issue.
