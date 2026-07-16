# BugFund base image — stripped, non-root foundation for all sandbox tiers.
# Build:  docker build -t bugfund/base -f execution_engine/images/base/Dockerfile .
#
# Principles: smallest practical surface, no compilers, no package manager cache,
# a non-root runtime user, and python3 on PATH (the PoV executor contract).
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Minimal runtime: python3 + ca-certificates + tini (PID 1 / signal handling).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates python3 python3-distlib tini \
 && rm -rf /var/lib/apt/lists/*

# Non-root runtime user; everything untrusted runs as `bugfund`.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 bugfund

# Writable tmp only; rootfs is otherwise read-only (enforced at `docker run`).
RUN mkdir -p /srv/target /srv/pov && chown -R bugfund:bugfund /srv /home/bugfund

USER bugfund
WORKDIR /home/bugfund

# tini reaps zombies and forwards signals so PoVs dying on SIGKILL are observed.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "--version"]
