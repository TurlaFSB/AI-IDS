# syntax=docker/dockerfile:1
#
# Base image: Docker Official Image python:3.12-slim, pulled from the AWS public mirror (same
# images and digests, avoids Docker Hub rate limits) and pinned by index digest.
ARG PYTHON_IMAGE=public.ecr.aws/docker/library/python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

FROM ${PYTHON_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
WORKDIR /build
# Dependencies first (cacheable), installed only if every hash matches the lock file.
COPY requirements/runtime.txt requirements/runtime.txt
RUN pip install --require-hashes -r requirements/runtime.txt
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-deps .

FROM ${PYTHON_IMAGE} AS runtime
RUN groupadd --system --gid 10001 aiids \
    && useradd --system --uid 10001 --gid aiids --no-create-home --shell /usr/sbin/nologin aiids
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
WORKDIR /app
# Run with `--read-only` and mount data and output directories explicitly.
ENTRYPOINT ["ai-ids"]
CMD ["--help"]
