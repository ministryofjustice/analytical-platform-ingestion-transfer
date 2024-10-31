.PHONY: build debug run

IMAGE_NAME ?= analytical-platform.service.justice.gov.uk/ingestion-transfer
IMAGE_TAG  ?= local

build:
	docker build --platform linux/amd64 --file Dockerfile --tag $(IMAGE_NAME):$(IMAGE_TAG) .

debug: build
	docker run -it --rm \
		--platform linux/amd64 \
		--hostname ingestion-scan \
		--name analytical-platform-ingestion-transfer \
		--entrypoint /bin/bash \
		$(IMAGE_NAME):$(IMAGE_TAG)
