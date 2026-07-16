# Builds the py-0.8-django4 interop entry: a server-only image providing the
# one declared runnable (manifest.yaml build.dockerfile). The orchestrator
# invokes it by full path:
#   /usr/local/bin/py-0.8-django4-server --transport http --addr ... \
#       --operator ... --allowlist ... [--mode ...]
#
# The valiss dependency is the frozen v0.8.0 git tag — never a local
# checkout — so the image pins the exact library the entry declares. The base
# is python:3.12-slim because Django 4.2 LTS supports Python only up to 3.12.
FROM python:3.12-slim AS build
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
        "valiss @ git+https://github.com/valiss-dev/valiss-py@v0.8.0" .

FROM python:3.12-slim
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels \
        valiss-interop-py-0-8-django4 && \
    rm -rf /wheels
