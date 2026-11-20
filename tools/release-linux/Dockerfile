# The toolchain that builds the Linux desktop app for releases
# (task release/desktop/linux). The app links GTK 4 and WebKitGTK 6.0 through
# cgo, so its bytes depend on the C compiler, the linker and the headers. Every
# one of them is pinned here: the base image and Go by digest, and the Ubuntu
# packages by an Ubuntu snapshot date, so the image installs the same package
# versions whenever and wherever it is built. Bump SNAPSHOT and the digests
# together, deliberately; a release can be rebuilt only with the Dockerfile of
# its tag.
FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS go

FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db

ARG SNAPSHOT=20261101T000000Z

# ca-certificates comes from the image's own archive first, only so that apt
# can reach the snapshot service over HTTPS; it does not touch the build. The
# snapshot service has no ubuntu-ports archive: its ubuntu archive holds the
# arm64 packages too.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -f /etc/apt/sources.list.d/*; \
    printf '%s\n' \
      'Types: deb' \
      "URIs: https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT/" \
      'Suites: resolute resolute-updates resolute-security' \
      'Components: main universe' \
      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/snapshot.sources; \
    rm -rf /var/lib/apt/lists/*; \
    apt-get update; \
    apt-get install -y --no-install-recommends gcc libc6-dev pkg-config libgtk-4-dev libwebkitgtk-6.0-dev; \
    rm -rf /var/lib/apt/lists/*

COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    HOME=/tmp \
    GOCACHE=/tmp/go-cache
