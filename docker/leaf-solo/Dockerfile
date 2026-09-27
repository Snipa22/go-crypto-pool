# syntax=docker/dockerfile:1
#
# docker/leaf-solo/Dockerfile
#
# Builds cmd/leaf-solo, the standalone-solo leaf mining-proxy mode.
#
# Runtime base: gcr.io/distroless/static-debian12. leaf-solo never
# shells out (no os/exec usage in this package tree) but talks
# directly to a Monero-family node over RPC/ZMQ and may reach a
# backend/notification endpoint over HTTPS, so it needs CA
# certificates for outbound TLS verification. distroless/static ships
# ca-certificates and a built-in nonroot (65532:65532) user, covering
# both needs without a shell or package manager.

FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/leaf-solo \
    ./cmd/leaf-solo

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/leaf-solo /usr/local/bin/leaf-solo

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/leaf-solo"]
