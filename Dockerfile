FROM rust:bookworm AS builder

ENV OPENSSL_NO_VENDOR=1
ENV PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig

WORKDIR /app
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src
RUN cargo install diesel_cli --no-default-features --features postgres

COPY . .

RUN cargo build --release --verbose

FROM rust:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/authentication /usr/local/bin/authentication
COPY --from=builder /usr/local/cargo/bin/diesel /usr/local/bin/diesel
COPY migrations ./migrations
COPY diesel.toml .

CMD ["sh", "-c", "diesel migration run && authentication"]
