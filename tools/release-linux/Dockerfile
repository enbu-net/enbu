# The toolchain that builds the Linux desktop app for releases
# (task release/desktop/linux). The app links GTK 4 and WebKitGTK 6.0 through
# cgo, so its bytes depend on the C compiler, the linker and the headers. Every
# one of them is pinned here: the base image and Go by digest, and the Ubuntu
# packages by an Ubuntu snapshot date, so the image installs the same package
# versions whenever and wherever it is built. Bump SNAPSHOT and the digests
# together, deliberately; a release can be rebuilt only with the Dockerfile of
# its tag.
FROM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS go

FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c

ARG SNAPSHOT=20261101T000000Z

# ca-certificates comes from the image's own archive first, only so that apt
# can reach the snapshot service over HTTPS; it does not touch the build.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    case "$(dpkg --print-architecture)" in \
      amd64) archive=ubuntu ;; \
      *) archive=ubuntu-ports ;; \
    esac; \
    rm -f /etc/apt/sources.list.d/*; \
    printf '%s\n' \
      'Types: deb' \
      "URIs: https://snapshot.ubuntu.com/$archive/$SNAPSHOT/" \
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
