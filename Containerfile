# MCP Airlock CrunchTools Container
# Built on Hummingbird Python image (Red Hat UBI-based) for enterprise security
#
# Build:
#   podman build -t quay.io/crunchtools/mcp-airlock .
#
# Run (Streamable HTTP on port 8019):
#   podman run --rm \
#     --env-file ~/.config/mcp-env/mcp-quarantine.env \
#     -v ~/.local/share/mcp-quarantine:/data:Z \
#     -p 127.0.0.1:8019:8019 \
#     quay.io/crunchtools/mcp-airlock \
#     --transport streamable-http --host 0.0.0.0 --port 8019
#
# With Claude Code (stdio):
#   claude mcp add mcp-airlock-crunchtools \
#     -- podman run -i --rm \
#     --env-file ~/.config/mcp-env/mcp-quarantine.env \
#     -v ~/.local/share/mcp-quarantine:/data:Z \
#     quay.io/crunchtools/mcp-airlock

FROM quay.io/hummingbird/python:latest

LABEL name="mcp-airlock-crunchtools" \
      version="0.1.0" \
      summary="Secure MCP server for quarantined web content extraction" \
      description="Two-layer defense against prompt injection: deterministic sanitization + quarantined LLM" \
      maintainer="crunchtools.com" \
      url="https://github.com/crunchtools/mcp-airlock" \
      io.k8s.display-name="MCP Airlock CrunchTools" \
      io.openshift.tags="mcp,security,prompt-injection,sanitization,quarantine" \
      org.opencontainers.image.source="https://github.com/crunchtools/mcp-airlock" \
      org.opencontainers.image.description="Secure MCP server for quarantined web content extraction" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

RUN python -c "from mcp_airlock_crunchtools import main; print('Installation verified')"

ENV QUARANTINE_DB=/data/quarantine.db

EXPOSE 8019
ENTRYPOINT ["python", "-m", "mcp_airlock_crunchtools"]
