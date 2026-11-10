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

| Asset | How it is built |
| --- | --- |
| `enbu_*` archives, `.deb`, `.rpm`, `.apk`, `.pkg.tar.zst` | GoReleaser, `CGO_ENABLED=0`, `-trimpath`, file times and owners fixed |
| `enbu-desktop_*_windows_*.zip` | cross-built on Linux without cgo, zipped by `tools/reproarchive` |
| `enbu-vscode_*.vsix` | `vsce package`, then rewritten by `tools/reproarchive` |

Every input is pinned: Go by `go.mod`, GoReleaser, nfpm, Node.js and pnpm by
`aqua.yaml`, the frontend and extension dependencies by their lockfiles, and
the Wails CLI by `tools/wails3/go.mod`. Times come from the commit
(`SOURCE_DATE_EPOCH`), never from the clock.

The release workflow enforces this. The `reproducible` job builds the assets
that are published; the `reproduce` job builds them again on a runner of the
other CPU architecture, from a fresh clone in another directory, with no Go,
tool or dependency cache. Nothing is signed or published unless every asset
matches. CI does the same on every pull request, so a change that breaks
reproducibility cannot be merged.

The Linux and macOS desktop apps (`enbu-desktop_*_linux_*`, `*.dmg`) are not
reproducible yet: they link against the runner's GTK 4 / WebKitGTK and the
macOS SDK through cgo. They are still signed and attested.

## Rebuild a release yourself

You need Linux (amd64 or arm64), Git, [aqua](https://aquaproj.github.io/) for
the pinned tools, the Vite+ CLI (`vp`) that the frontend tasks call, and the
GTK 4 and WebKitGTK 6.0 headers (`libgtk-4-dev libwebkitgtk-6.0-dev`), which
the Wails CLI needs to build even though the Windows app does not use them.

```sh
git clone https://github.com/enbu-net/enbu && cd enbu
git checkout vX.Y.Z
aqua install
task release/build VERSION=vX.Y.Z
```

Then compare with the published `checksums.txt`, after checking its signature
as above:

```sh
gh release download vX.Y.Z --repo enbu-net/enbu --pattern checksums.txt --dir dist/published
cd dist
sha256sum --ignore-missing -c published/checksums.txt
```

Every line must say `OK`, and the number of lines must match
`dist/reproducible.sha256`. A mismatch means the published asset is not what
the tag's source produces: please open an issue.
