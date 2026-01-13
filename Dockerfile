# syntax=docker/dockerfile:1.4

# Sentinel WAF Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-waf-agent /sentinel-waf-agent

LABEL org.opencontainers.image.title="Sentinel WAF Agent" \
      org.opencontainers.image.description="Sentinel WAF Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-waf"

ENV RUST_LOG=info,sentinel_waf_agent=debug \
    SOCKET_PATH=/var/run/sentinel/waf.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-waf-agent"]
