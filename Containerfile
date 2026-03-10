# MCP Airlock CrunchTools Container
# Three-layer defense: deterministic sanitization + Prompt Guard 2 classifier + quarantined LLM
# Built on Hummingbird Python image (Red Hat UBI-based) for enterprise security
#
# Build (requires HF_TOKEN for Llama model download):
#   podman build --secret id=hf_token,env=HF_TOKEN \
#     -t quay.io/crunchtools/mcp-airlock .
#
# Run (Streamable HTTP on port 8019):
#   podman run --rm \
#     --env-file ~/.config/mcp-env/mcp-airlock.env \
#     -v ~/.local/share/mcp-airlock:/data:Z \
#     -p 127.0.0.1:8019:8019 \
#     quay.io/crunchtools/mcp-airlock \
#     --transport streamable-http --host 0.0.0.0 --port 8019
#
# With Claude Code (stdio):
#   claude mcp add mcp-airlock-crunchtools \
#     -- podman run -i --rm \
#     --env-file ~/.config/mcp-env/mcp-airlock.env \
#     -v ~/.local/share/mcp-airlock:/data:Z \
#     quay.io/crunchtools/mcp-airlock

# ============================================================
# Stage 1: ONNX model conversion (builder — PyTorch + optimum)
# ============================================================
FROM quay.io/hummingbird/python:latest AS model-builder

RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir \
    optimum[onnxruntime] \
    transformers \
    sentencepiece

# Download and convert the official Meta Prompt Guard 2 22M model to ONNX
# Requires HF_TOKEN to access meta-llama gated model
RUN --mount=type=secret,id=hf_token \
    export HF_TOKEN=$(cat /run/secrets/hf_token) && \
    optimum-cli export onnx \
      --model meta-llama/Llama-Prompt-Guard-2-22M \
      --task text-classification \
      /models/prompt-guard-2-22m/

# ============================================================
# Stage 2: Runtime image (ONNX Runtime only — no PyTorch)
# ============================================================
FROM quay.io/hummingbird/python:latest

LABEL name="mcp-airlock-crunchtools" \
      version="0.2.0" \
      summary="Secure MCP server for quarantined web content extraction" \
      description="Three-layer defense against prompt injection: deterministic sanitization + Prompt Guard 2 classifier + quarantined LLM" \
      maintainer="crunchtools.com" \
      url="https://github.com/crunchtools/mcp-airlock" \
      io.k8s.display-name="MCP Airlock CrunchTools" \
      io.openshift.tags="mcp,security,prompt-injection,sanitization,quarantine" \
      org.opencontainers.image.source="https://github.com/crunchtools/mcp-airlock" \
      org.opencontainers.image.description="Secure MCP server for quarantined web content extraction" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      com.meta.llama.built-with="Built with Llama" \
      com.meta.llama.model="Llama-Prompt-Guard-2-22M" \
      com.meta.llama.license="Llama 4 Community License Agreement"

WORKDIR /app

# Copy ONNX model files from builder stage (no PyTorch in final image)
COPY --from=model-builder /models/prompt-guard-2-22m/ /models/prompt-guard-2-22m/

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

RUN python -c "from mcp_airlock_crunchtools import main; print('Installation verified')"

ENV QUARANTINE_DB=/data/quarantine.db
ENV CLASSIFIER_MODEL_PATH=/models/prompt-guard-2-22m

EXPOSE 8019
ENTRYPOINT ["python", "-m", "mcp_airlock_crunchtools"]
