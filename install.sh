#!/bin/bash -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Build the opencode image: cybergym/opencode:latest
# Pin a specific CLI version with: OPENCODE_VERSION=1.18.1 bash install.sh
# Skip the cybersecurity-skills clone with: CYBERSEC_SKILLS=0 bash install.sh
# Pin a specific skills ref with:           CYBERSEC_SKILLS_REF=v1.1.0 bash install.sh
echo "Building cybergym/opencode:latest ..."
docker build \
    --build-arg "OPENCODE_VERSION=${OPENCODE_VERSION:-latest}" \
    --build-arg "CYBERSEC_SKILLS=${CYBERSEC_SKILLS:-1}" \
    --build-arg "CYBERSEC_SKILLS_REF=${CYBERSEC_SKILLS_REF:-main}" \
    -t cybergym/opencode:latest \
    -f "./Dockerfile" .

# This agent reads API credentials from the environment; the container is
# seeded with ~/.local/share/opencode/auth.json at run time only if no
# provider env var (ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_* / ...) is set.
if [ -n "${ANTHROPIC_API_KEY:-}" ] || [ -n "${OPENAI_API_KEY:-}" ] \
   || [ -n "${ANTHROPIC_AUTH_TOKEN:-}" ]; then
    echo "Found provider API key in environment; container will use it directly."
elif [ -f "${HOME}/.local/share/opencode/auth.json" ]; then
    echo "Found login at ${HOME}/.local/share/opencode/auth.json"
else
    echo "No auth found. Either:"
    echo "  - export ANTHROPIC_API_KEY / OPENAI_API_KEY (recommended for CI), or"
    echo "  - run 'opencode auth login' on the host to create ~/.local/share/opencode/auth.json"
fi
