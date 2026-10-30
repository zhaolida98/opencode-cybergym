FROM node:20-slim

ARG TZ
ENV TZ="$TZ"

# Version of the opencode CLI to install (npm tag or exact version).
# See https://www.npmjs.com/package/opencode-ai for available versions.
ARG OPENCODE_VERSION=1.18.1

# Basic tooling plus what an agent typically needs to develop a PoC: a compiler,
# a debugger, python, and the usual file inspection utilities.
RUN apt-get update && apt-get install -y --no-install-recommends \
  bsdmainutils build-essential ca-certificates curl dnsutils file gdb git \
  gnupg2 jq less procps python3 python3-dev python3-pip ripgrep unzip vim zsh \
  && rm -rf /var/lib/apt/lists/*

# Install global npm packages into a shared prefix on PATH.
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin

# Install the opencode CLI.
RUN npm install -g "opencode-ai@${OPENCODE_VERSION}" \
  && npm cache clean --force

# --- Optional: Anthropic Cybersecurity Skills library (817 skills, ~48MB) -----
# Baked into the image at build time so runtime never needs internet to fetch it.
# Discovery is off by default in run.py; opt-in per run with `--skills on`
# (which injects {"skills": {"paths": ["/opt/anthropic-cybersecurity-skills/skills"]}}
# into OPENCODE_CONFIG_CONTENT). See README.md for the token-cost caveat.
#
# Skip the clone at build time with:  --build-arg CYBERSEC_SKILLS=0
ARG CYBERSEC_SKILLS=1
ARG CYBERSEC_SKILLS_REPO=https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git
ARG CYBERSEC_SKILLS_REF=main
RUN if [ "$CYBERSEC_SKILLS" = "1" ]; then \
      git clone --depth 1 --branch "$CYBERSEC_SKILLS_REF" \
        "$CYBERSEC_SKILLS_REPO" /opt/anthropic-cybersecurity-skills \
      && rm -rf /opt/anthropic-cybersecurity-skills/.git ; \
    else \
      echo "Skipping cybersecurity-skills clone (CYBERSEC_SKILLS=0)" ; \
    fi

WORKDIR /workspace
