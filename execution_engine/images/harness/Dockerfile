# BugFund harness image — per-target-type build/test harnesses.
# Build:  docker build -t bugfund/harness -f execution_engine/images/harness/Dockerfile .
#
# Built ON the base image; adds the toolchains needed to compile targets with
# sanitizers (ASan/UBSan) and to run lightweight fuzz harnesses. Heavier
# analyzers (semgrep, nuclei) run on the host control plane, not here.
FROM bugfund/base

USER root

ENV DEBIAN_FRONTEND=noninteractive

# Build toolchain + sanitizer runtimes + common test deps. clang preferred for
# ASan/UBSan/fuzzer instrumentation; gcc kept for targets that need it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential clang llvm cmake make autoconf automake pkg-config \
      git libasan6 libubsan1 libfuzzer-14-dev \
      python3-dev python3-pip \
 && rm -rf /var/lib/apt/lists/*

# Common Python test deps only; no network at runtime so install now.
RUN pip3 install --no-cache-dir --break-system-packages pytest || pip3 install --no-cache-dir pytest

USER bugfund
WORKDIR /srv
CMD ["python3", "--version"]
