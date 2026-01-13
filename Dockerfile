FROM rust:1.88 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

RUN cargo install diesel_cli --no-default-features --features postgres

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/authentication /usr/local/bin/authentication
COPY --from=builder /usr/local/cargo/bin/diesel /usr/local/bin/diesel

COPY migrations ./migrations
COPY diesel.toml .

CMD ["diesel", "run", "migrations", "&&", "authentication"]

