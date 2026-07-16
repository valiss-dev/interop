# Builds the py-0.8-asgi3 interop entry: a server-only image providing the
# one declared runnable (manifest.yaml build.dockerfile). The orchestrator
# invokes it by full path:
#   /usr/local/bin/py-0.8-asgi3-server --transport http --addr ... \
#       --operator ... --allowlist ... [--mode ...]
#
# The valiss dependency is the frozen v0.8.0 git tag — never a local
# checkout — so the image pins the exact library the entry declares; the
# entry package's own pins supply starlette (the shipped ASGI middlewares'
# import) and uvicorn (the single-process host).
FROM python:3.13-slim AS build
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
        "valiss @ git+https://github.com/valiss-dev/valiss-py@v0.8.0" .

FROM python:3.13-slim
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels \
        valiss-interop-py-0-8-asgi && \
    rm -rf /wheels
