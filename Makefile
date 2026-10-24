SHELL := /bin/bash
PROFILE ?=
HARDWARE ?= cpu
.PHONY: check builder build smoke smoke-split package enrollment cpu-serving

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

enrollment:
	@test "$(HARDWARE)" = cpu
	docker build -t outerspace-enrollment:dev -f build-support/enrollment.Dockerfile .
	python3 scripts/test-enrollment.py --profile "$(PROFILE)" --output "build/$$(python3 scripts/profiles.py directory --profile '$(PROFILE)' --hardware cpu)"

cpu-serving:
	@test "$(PROFILE)" = inference
	@test "$(HARDWARE)" = cpu
	docker build -t outerspace-enrollment:dev -f build-support/enrollment.Dockerfile .
	python3 scripts/test-enrollment.py --profile inference --cpu-serving --output "build/$$(python3 scripts/profiles.py directory --profile inference --hardware cpu)"
