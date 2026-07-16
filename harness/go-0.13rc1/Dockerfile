# Builds the go-0.13rc1 interop entry: one image providing both declared
# runnables (manifest.yaml build.dockerfile). The orchestrator invokes them
# by full path — the runtime image is distroless and has no shell:
#   /usr/local/bin/go-0.13rc1-server --transport ... --addr ... \
#       --operator ... --allowlist ... [--mode ...]
#   /usr/local/bin/go-0.13rc1-client --transport ... --addr ... --creds ... \
#       [--nonce ...] [--mode ...] [--audience ...] [--payload ...] \
#       [--tamper-payload ...] [--ttl ...] [--chain ...]
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/go-0.13rc1-server ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -o /out/go-0.13rc1-client ./cmd/client

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/go-0.13rc1-server /usr/local/bin/go-0.13rc1-server
COPY --from=build /out/go-0.13rc1-client /usr/local/bin/go-0.13rc1-client
