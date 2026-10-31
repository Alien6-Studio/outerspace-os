ARG BUILDER=outerspace-builder:dev
FROM ${BUILDER}
# The base already pins the Ubuntu snapshot. Kernel tools stay in this separate
# builder, so changing them does not invalidate the Rust/Go runtime cache.
RUN apt-get update && apt-get install -y --no-install-recommends flex bison bc libelf-dev dwarves ccache && rm -rf /var/lib/apt/lists/*
RUN dpkg-query --show --showformat='${Package}\t${Version}\t${Architecture}\n' \
    > /opt/outerspace/kernel-builder-packages.tsv
