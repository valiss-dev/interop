# Builds the go-0.13-gin interop entry: one image providing the one
# declared runnable (manifest.yaml build.dockerfile; the entry is
# server-only). The orchestrator invokes it by full path, since the runtime
# image is distroless and has no shell:
#   /usr/local/bin/go-0.13-gin-server --transport http --addr ... \
#       --operator ... --allowlist ... [--mode ...]
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/go-0.13-gin-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/go-0.13-gin-server /usr/local/bin/go-0.13-gin-server
