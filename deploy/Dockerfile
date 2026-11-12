# syntax=docker/dockerfile:1
# meiscope-collector container image (ghcr.io/uvamai/meiscope-collector).
# Build from the repository root:
#   docker build -f deploy/Dockerfile -t meiscope-collector:dev .
# Base images are pinned by digest (tags kept for readability); refresh both
# together, never one alone.

# The build stage runs on the build machine's platform and cross-compiles
# (pure Go, CGO off), so an arm64 image needs no emulation: the final stage
# only copies the binary.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ARG VERSION=0.0.0-dev
ARG COMMIT=none
ARG TARGETOS=linux
ARG TARGETARCH=amd64
# GO-2026-6859 (net/http) is fixed in go1.27.4. Until the base image is
# refreshed to golang:1.27.4-alpine by digest, the go command fetches the
# go1.27.4 toolchain, verified against the Go checksum database.
ENV GOTOOLCHAIN=go1.27.4 CGO_ENABLED=0
WORKDIR /src
COPY go.mod ./
# go.sum does not exist while the module has no dependencies; the wildcard
# keeps this line valid before and after WP0.3 adds them.
COPY go.su[m] ./
RUN go mod download
COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/uvamai/meiscope-collector/internal/platform.Version=${VERSION} -X github.com/uvamai/meiscope-collector/internal/platform.Commit=${COMMIT}" \
      -o /out/meiscope-collector ./cmd/meiscope-collector
# An empty state directory, so a volume mounted on it is writable by nonroot.
RUN mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.source="https://github.com/uvamai/meiscope-collector" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.url="https://meiscope.cloud" \
      org.opencontainers.image.authors="hello@meiscope.cloud" \
      org.opencontainers.image.title="meiscope-collector"
COPY --from=build /out/meiscope-collector /usr/bin/meiscope-collector
# The enrolled identity (MEISCOPE_STATE_DIR); mount a volume here.
COPY --from=build --chown=65532:65532 /out/state /var/lib/meiscope-collector
# Inside a container the health endpoint listens on all interfaces so the
# orchestrator can reach GET /healthz; publish the port only on a private
# network. /status, /pause and /resume still answer loopback callers only
# (peer address and Host header); call them from a helper container in this
# container's network namespace, e.g.
#   docker run --rm --network container:<name> <curl image> -X POST http://127.0.0.1:8090/pause
# (docs/install.md, "Local listener"). MEISCOPE_STATUS_REMOTE=true opens /status.
ENV MEISCOPE_HEALTH_ADDR=0.0.0.0:8090
EXPOSE 8090
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/meiscope-collector"]
CMD ["run"]
