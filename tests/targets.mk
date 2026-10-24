# Local and CI qualification; none of these tools are installed in the OS.
.PHONY: check smoke smoke-split enrollment cpu-serving

check:
	$(PYTHON) -m unittest discover -s tests/unit -v
	@set -euo pipefail; for script in build/*.sh tests/harness/*.sh src/image/mkosi.postinst src/image/mkosi.extra/usr/lib/outerspace/*; do bash -n "$$script"; done

smoke smoke-split:
	@set -euo pipefail; \
	directory=$$($(PYTHON) build/tools/profiles.py directory --profile "$(PROFILE)" --hardware "$(HARDWARE)"); \
	script=boot-uefi.py; if [[ "$@" = smoke-split ]]; then script=boot-smoke.py; fi; \
	docker run --rm --cap-drop=ALL --user "$$(id -u):$$(id -g)" \
	    --mount "type=bind,src=$(CURDIR),dst=/work,readonly" \
	    --mount "type=bind,src=$(OUT_DIR)/$$directory,dst=/out" \
	    "$(OUTERSPACE_BUILDER)" python3 "/work/tests/harness/$$script" /out "$(PROFILE)" "$(HARDWARE)"

enrollment cpu-serving:
	@set -euo pipefail; \
	directory=$$($(PYTHON) build/tools/profiles.py directory --profile "$(PROFILE)" --hardware "$(HARDWARE)"); \
	if [[ "$(HARDWARE)" != cpu ]]; then echo 'Enrollment requires HARDWARE=cpu.' >&2; exit 2; fi; \
	serving=; \
	if [[ "$@" = cpu-serving ]]; then \
	    if [[ "$(PROFILE)" != inference ]]; then echo 'CPU serving requires PROFILE=inference.' >&2; exit 2; fi; \
	    serving=--cpu-serving; \
	fi; \
	docker build --build-arg "BUILDER=$(OUTERSPACE_BUILDER)" -t outerspace-enrollment:dev -f tests/Dockerfile .; \
	$(PYTHON) tests/harness/enrollment.py --profile "$(PROFILE)" $${serving:+"$$serving"} --output "$(OUT_DIR)/$$directory"
