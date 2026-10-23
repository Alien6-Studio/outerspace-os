SHELL := /bin/bash
PROFILE ?=
HARDWARE ?= cpu
.PHONY: check builder build smoke smoke-split package

check:
	python3 -m unittest discover -s tests -v
	for script in scripts/*.sh image/mkosi.postinst image/mkosi.extra/usr/lib/outerspace/*; do bash -n "$$script" || exit; done

builder:
	docker build -t outerspace-builder:dev -f build-support/Dockerfile .

build:
	./scripts/build.sh "$(PROFILE)" "$(HARDWARE)"

smoke:
	./scripts/smoke.sh "$(PROFILE)" "$(HARDWARE)" uefi

smoke-split:
	./scripts/smoke.sh "$(PROFILE)" "$(HARDWARE)" split

package:
	./scripts/package.sh "$(PROFILE)" "$(HARDWARE)"
