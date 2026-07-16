# Builds the py-0.8 interop entry: one image providing both declared
# runnables (manifest.yaml build.dockerfile). The orchestrator invokes them
# by full path:
#   /usr/local/bin/py-0.8-server --transport ... --addr ... \
#       --operator ... --allowlist ... [--mode ...]
#   /usr/local/bin/py-0.8-client --transport ... --addr ... --creds ... \
#       [--nonce ...] [--mode ...] [--audience ...] [--payload ...]
#
# The valiss dependency is the frozen v0.8.0 git tag — never a local
# checkout — so the image pins the exact library the entry declares.
FROM python:3.13-slim AS build
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir grpcio-tools==1.82.1 && \
    python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. \
        interoppb/interop.proto
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
        "valiss @ git+https://github.com/valiss-dev/valiss-py@v0.8.0" .

FROM python:3.13-slim
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels \
        valiss-interop-py-0-8 && \
    rm -rf /wheels
