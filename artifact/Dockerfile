# v4 artifact container (TASKS F2). Build from the repository root:
#   docker build -f artifact/Dockerfile -t pqid-v4 .
#   docker run --rm pqid-v4                      # full rebuild + checks (artifact/rebuild.sh)
#   docker run --rm pqid-v4 bash artifact/rebuild.sh --quick
#
# Pins: artifact/toolchain.env (Node tarball checked against its published sha256).
# circom, Foundry and Tectonic come from their GitHub release assets, each checked against the
# sha256 in artifact/toolchain.env (recorded at the first build, 2026-09-29; fail closed since).
# The base image is pinned by digest (first build 2026-09-29).
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils git build-essential python3 python3-venv python3-pip \
      fontconfig libfontconfig1 libgraphite2-3 libharfbuzz0b libicu74 libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY artifact/toolchain.env /opt/pqid/toolchain.env
COPY artifact/requirements.txt /opt/pqid/requirements.txt

# Node (ships OpenSSL 3.5 with ML-DSA and ML-KEM)
RUN set -eux; . /opt/pqid/toolchain.env; \
    f="node-v${NODE_VERSION}-linux-x64.tar.xz"; \
    curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/${f}"; \
    echo "${NODE_SHA256}  ${f}" | sha256sum -c -; \
    tar -xJf "$f" -C /usr/local --strip-components=1; rm "$f"; \
    echo "${NODE_SHA256}  ${f}" >> /opt/pqid/downloads.sha256

# circom, Foundry (anvil), Tectonic
RUN set -eux; . /opt/pqid/toolchain.env; cd /tmp; \
    curl -fsSL -o circom "https://github.com/iden3/circom/releases/download/v${CIRCOM_VERSION}/circom-linux-amd64"; \
    echo "${CIRCOM_SHA256}  circom" | sha256sum -c -; sha256sum circom >> /opt/pqid/downloads.sha256; install -m 0755 circom /usr/local/bin/circom; \
    curl -fsSL -o foundry.tgz "https://github.com/foundry-rs/foundry/releases/download/v${FOUNDRY_VERSION}/foundry_v${FOUNDRY_VERSION}_linux_amd64.tar.gz"; \
    echo "${FOUNDRY_SHA256}  foundry.tgz" | sha256sum -c -; sha256sum foundry.tgz >> /opt/pqid/downloads.sha256; tar -xzf foundry.tgz -C /usr/local/bin anvil; \
    curl -fsSL -o tectonic.tgz "https://github.com/tectonic-typesetting/tectonic/releases/download/tectonic%40${TECTONIC_VERSION}/tectonic-${TECTONIC_VERSION}-x86_64-unknown-linux-musl.tar.gz"; \
    echo "${TECTONIC_SHA256}  tectonic.tgz" | sha256sum -c -; sha256sum tectonic.tgz >> /opt/pqid/downloads.sha256; tar -xzf tectonic.tgz -C /usr/local/bin tectonic; \
    rm -f circom foundry.tgz tectonic.tgz; \
    circom --version; anvil --version; tectonic --version

WORKDIR /work
COPY . /work
# Python tools in the repo-local venv the v4 interop test looks for (.venv)
RUN python3 -m venv /work/.venv && /work/.venv/bin/pip install --no-cache-dir -r /opt/pqid/requirements.txt
ENV PATH="/work/.venv/bin:${PATH}" \
    PQID_PYTHON=/work/.venv/bin/python \
    PQID_TECTONIC=/usr/local/bin/tectonic
RUN npm ci --no-audit --no-fund

CMD ["bash", "artifact/rebuild.sh"]
