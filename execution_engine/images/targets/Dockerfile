# BugFund target ingestion image — clones & packages an ingested target.
# Build:  docker build -t bugfund/target -f execution_engine/images/targets/Dockerfile .
#
# Used by the ingestion pipeline to fetch a submitted repo at a pinned commit
# and produce a reproducible, buildable source tree under /srv/target. The
# compiled artifacts are then fed to the harness image for PoV execution.
FROM bugfund/base

USER root

ENV DEBIAN_FRONTEND=noninteractive

# Ingestion needs: git (clone/pin), common build deps, and jq for recipe parsing.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git curl jq build-essential make \
 && rm -rf /var/lib/apt/lists/*

# The ingestion entrypoint reads TARGET_REPO / TARGET_COMMIT / BUILD_INSTRUCTIONS
# (JSON), clones the repo, checks out the commit, and runs the build recipe.
COPY --chown=bugfund:bugfund ingest.sh /usr/local/bin/ingest
RUN chmod +x /usr/local/bin/ingest

USER bugfund
WORKDIR /srv

# Actual repo is bind-mounted or cloned at run time by the control plane.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ingest"]
