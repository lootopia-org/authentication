FROM rust:1.88 as builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpq-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install diesel_cli --no-default-features --features postgres

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/target/release/authentication .
COPY --from=builder /usr/local/cargo/bin/diesel /usr/local/bin/diesel

COPY migrations ./migrations
COPY diesel.toml .

CMD sh -c '\
  echo "Waiting for Postgres..." && \
  until diesel database setup >/dev/null 2>&1; do sleep 1; done && \
  echo "Running migrations..." && \
  diesel migration run && \
  echo "Starting app..." && \
  exec ./authentication \
'

