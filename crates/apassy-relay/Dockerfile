# syntax=docker/dockerfile:1
# Build context: the repository root, so the core crate and the workspace lock are in it:
#   docker build -f crates/apassy-relay/Dockerfile .
# Dockerfile.dockerignore next to this file limits the context to what the build reads.
FROM rust:1.97.0-trixie AS build
ARG APASSY_RELEASE_VERSION
ARG APASSY_RELEASE_COMMIT=unknown
ENV APASSY_RELEASE_COMMIT=$APASSY_RELEASE_COMMIT
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p apassy-relay --bin apassy-relay --bin apassy-team

FROM debian:trixie-slim
ARG APASSY_RELEASE_VERSION
ARG APASSY_RELEASE_COMMIT=unknown
LABEL org.opencontainers.image.title="apassy-relay" \
      org.opencontainers.image.version=$APASSY_RELEASE_VERSION \
      org.opencontainers.image.revision=$APASSY_RELEASE_COMMIT \
      org.opencontainers.image.source="https://github.com/wydrox/apassy" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin relay \
 && mkdir -p /data && chown 10001:10001 /data && chmod 0700 /data
COPY --from=build /src/target/release/apassy-relay /src/target/release/apassy-team /usr/local/bin/
USER 10001:10001
# The hosted relay serves no shared team vaults or proxy (ADR 0037, D8). A user's own
# node keeps the default, 1.
ENV APASSY_RELAY_DATA=/data APASSY_RELAY_LISTEN=0.0.0.0:8080 APASSY_RELAY_TEAM_VAULTS=0
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/apassy-relay"]
CMD ["serve"]
