# Test tooling only; never installed in the OS image.
FROM outerspace-builder:dev
RUN apt-get update && apt-get install -y --no-install-recommends dnsmasq-base iproute2 \
    && rm -rf /var/lib/apt/lists/*
