#checkov:skip=CKV_DOCKER_2: HEALTHCHECK not required - AWS Lambda does not support HEALTHCHECK
#checkov:skip=CKV_DOCKER_3: USER not required - A non-root user is used by AWS Lambda
FROM public.ecr.aws/lambda/python:3.12@sha256:1d922f123370801843aad18d0911759c55402af4d0dddb601181df4ed42b2ce2

LABEL org.opencontainers.image.vendor="Ministry of Justice" \
      org.opencontainers.image.authors="Analytical Platform (analytical-platform@digital.justice.gov.uk)" \
      org.opencontainers.image.title="Ingestion Transfer" \
      org.opencontainers.image.description="Ingestion transfer image for Analytical Platform" \
      org.opencontainers.image.url="https://github.com/ministryofjustice/analytical-platform"

RUN microdnf update \
    && microdnf install --assumeyes \
         clamav-0.103.9-1.amzn2023.0.2.x86_64 \
         clamav-update-0.103.9-1.amzn2023.0.2.x86_64 \
         clamd-0.103.9-1.amzn2023.0.2.x86_64 \
         tar-2:1.34-1.amzn2023.0.4.x86_64 \
    && microdnf clean all

COPY --chown=nobody:nobody --chmod=0755 src/var/task/ ${LAMBDA_TASK_ROOT}

RUN python -m pip install --no-cache-dir --upgrade pip==24.0 \
    && python -m pip install --no-cache-dir --requirement requirements.txt

CMD ["handler.handler"]
