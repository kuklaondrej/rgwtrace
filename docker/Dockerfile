# Pinned by the multi-arch image index digest so the build does not silently
# follow tag updates. Refresh when bumping the toolchain:
#   docker buildx imagetools inspect rust:1.90-bookworm   # top-level "Digest:"
FROM rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f

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
