# Build stage.
FROM golang:1.25-alpine AS build

WORKDIR /src

# Dependencies are copied first so the module layer caches independently of
# source edits. go.sum is committed, so this build is reproducible.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# Static, stripped, reproducible. CGO is off so the binary runs on distroless
# with no libc at all, which is what removes the shell from the final image.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/mesh    ./cmd/mesh && \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/api     ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/worker  ./cmd/worker && \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/simulator ./cmd/simulator && \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/meshctl ./cmd/meshctl

# Runtime stage.
#
# distroless static: no shell, no package manager, no libc. If the process is
# compromised there is nothing on the filesystem to pivot with. The nonroot tag
# runs as uid 65532 — a container that can write its own binary is a container
# an attacker can persist in.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/api       /usr/local/bin/api
COPY --from=build /out/worker    /usr/local/bin/worker
COPY --from=build /out/simulator /usr/local/bin/simulator
COPY --from=build /out/meshctl   /usr/local/bin/meshctl
COPY --from=build /out/mesh      /usr/local/bin/mesh

USER nonroot:nonroot
EXPOSE 8080

# Readiness, not liveness: this asks whether dependencies are healthy and
# migrations are current, which is the question an orchestrator needs answered
# before it sends traffic.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/meshctl", "health", "--endpoint", "http://127.0.0.1:8080/readyz"]

ENTRYPOINT ["/usr/local/bin/api"]
