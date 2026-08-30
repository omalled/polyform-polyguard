FROM rust:1-slim-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked --bin polyguard

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --no-create-home polyguard
COPY --from=builder /build/target/release/polyguard /usr/local/bin/polyguard
USER 10001:10001
EXPOSE 8443 9090
ENTRYPOINT ["/usr/local/bin/polyguard"]
CMD ["--config", "/etc/polyguard/polyguard.toml"]
