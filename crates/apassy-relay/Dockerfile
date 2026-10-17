# syntax=docker/dockerfile:1
FROM rust:1.97.0-trixie AS build
ARG APASSY_RELEASE_VERSION
ARG APASSY_RELEASE_COMMIT=unknown
ENV APASSY_RELEASE_COMMIT=$APASSY_RELEASE_COMMIT
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY src src
RUN cargo build --release --locked --bin apassy-relay --bin apassy-team

FROM debian:trixie-slim
ARG APASSY_RELEASE_VERSION
ARG APASSY_RELEASE_COMMIT=unknown
LABEL org.opencontainers.image.title="apassy-relay" \
      org.opencontainers.image.version=$APASSY_RELEASE_VERSION \
      org.opencontainers.image.revision=$APASSY_RELEASE_COMMIT \
      org.opencontainers.image.source="https://github.com/wydrox/apassy-relay"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin relay \
 && mkdir -p /data && chown 10001:10001 /data && chmod 0700 /data
COPY --from=build /src/target/release/apassy-relay /src/target/release/apassy-team /usr/local/bin/
USER 10001:10001
ENV APASSY_RELAY_DATA=/data APASSY_RELAY_LISTEN=0.0.0.0:8080
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/apassy-relay"]
CMD ["serve"]
