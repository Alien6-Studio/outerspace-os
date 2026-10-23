SHELL := /bin/bash
.PHONY: check builder build smoke smoke-split package

check:
	python3 -m unittest discover -s tests -v
	for script in scripts/*.sh image/mkosi.postinst image/mkosi.extra/usr/lib/outerspace/*; do bash -n "$$script" || exit; done

builder:
	docker build -t outerspace-builder:dev -f build-support/Dockerfile .

build:
	./scripts/build.sh

smoke:
	./scripts/smoke.sh

smoke-split:
	./scripts/smoke.sh split

package:
	./scripts/package.sh
