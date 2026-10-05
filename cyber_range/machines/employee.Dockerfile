FROM docker.io/library/ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl procps \
    && rm -rf /var/lib/apt/lists/*
