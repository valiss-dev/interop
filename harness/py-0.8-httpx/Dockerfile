# Builds the py-0.8-httpx interop entry: a client-only image providing the
# one declared runnable (manifest.yaml build.dockerfile). The orchestrator
# invokes it by full path:
#   /usr/local/bin/py-0.8-httpx-client --transport http --addr ... --creds ... \
#       [--nonce ...] [--mode ...] [--audience ...] [--payload ...] \
#       [--tamper-payload ...] [--ttl ...] [--chain ...]
#
# The valiss dependency is the frozen v0.8.0 git tag — never a local
# checkout — so the image pins the exact library the entry declares; the
# httpx extra pulls in the adapter surface this entry exercises.
FROM python:3.13-slim AS build
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
        "valiss[httpx] @ git+https://github.com/valiss-dev/valiss-py@v0.8.0" .

FROM python:3.13-slim
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels \
        valiss-interop-py-0-8-httpx && \
    rm -rf /wheels
