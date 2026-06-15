FROM rust:1.90-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        libelf-dev \
        llvm \
        linux-libc-dev \
        make \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt

WORKDIR /workspace
COPY . /workspace

RUN cargo build --release
