FROM rust:1.88 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpq-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install diesel_cli --no-default-features --features postgres

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/target/release/authentication .
COPY --from=builder /usr/local/cargo/bin/diesel /usr/local/bin/diesel

COPY migrations ./migrations
COPY diesel.toml .

CMD ["authentication"]

