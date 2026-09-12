# syntax=docker/dockerfile:1
#
# docker/backend/Dockerfile
#
# Builds cmd/backend, the unified go-crypto-pool backend service.
#
# Runtime base: gcr.io/distroless/static-debian12. The backend never
# shells out (no os/exec usage in this package tree) but does make
# outbound HTTPS/GRPC calls (Tari base-node GRPC, wallet RPC), so it
# needs CA certificates for TLS verification. distroless/static
# ships ca-certificates and a built-in nonroot (65532:65532) user,
# which covers both needs without pulling in a shell or package
# manager.

FROM golang:1.25-bookworm AS builder

WORKDIR /src

# Cache go.mod/go.sum download separately from source for better
# layer caching across builds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/backend \
    ./cmd/backend

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/backend /usr/local/bin/backend

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/backend"]
