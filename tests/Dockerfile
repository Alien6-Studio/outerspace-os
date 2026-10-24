# Test tooling only; never installed in the OS image.
ARG BUILDER=outerspace-builder:dev
FROM ${BUILDER}
RUN apt-get update && apt-get install -y --no-install-recommends dnsmasq-base iproute2 \
    && rm -rf /var/lib/apt/lists/*
