# Local and CI qualification; none of these tools are installed in the OS.
.PHONY: check smoke smoke-split enrollment cpu-serving agent-isolation agent-admission clean-test-cache
PRUNE_TEST_IMAGES = docker image prune --force --filter label=io.outerspace.tooling=true

# Preserve the test's exit status; failed cleanup must also fail a passing test.
define cleanup_test_images
cleanup_test_images() { \
    status=$$?; trap - EXIT; \
    if ! $(PRUNE_TEST_IMAGES); then \
        if [[ $$status -eq 0 ]]; then status=1; fi; \
    fi; \
    exit "$$status"; \
}; trap cleanup_test_images EXIT;
endef

clean-test-cache:
	$(PRUNE_TEST_IMAGES)

check:
	$(PYTHON) -m unittest discover -s tests/unit -v
	@set -euo pipefail; for script in build/*.sh tests/harness/*.sh tests/integration/*.sh src/image/mkosi.postinst src/image/mkosi.version src/image/mkosi.extra/usr/lib/outerspace/*; do bash -n "$$script"; done

smoke smoke-split:
	@set -euo pipefail; \
	directory=$$($(PYTHON) build/tools/profiles.py directory --profile "$(PROFILE)" --hardware "$(HARDWARE)"); \
	$(cleanup_test_images) \
	script=boot-uefi.py; if [[ "$@" = smoke-split ]]; then script=boot-smoke.py; fi; \
	docker run --rm --cap-drop=ALL --user "$$(id -u):$$(id -g)" \
	    --mount "type=bind,src=$(CURDIR),dst=/work,readonly" \
	    --mount "type=bind,src=$(OUT_DIR)/$$directory,dst=/out" \
	    "$(OUTERSPACE_BUILDER)" python3 "/work/tests/harness/$$script" /out "$(PROFILE)" "$(HARDWARE)"

enrollment cpu-serving agent-isolation:
	@set -euo pipefail; \
	directory=$$($(PYTHON) build/tools/profiles.py directory --profile "$(PROFILE)" --hardware "$(HARDWARE)"); \
	if [[ "$(HARDWARE)" != cpu ]]; then echo 'Enrollment requires HARDWARE=cpu.' >&2; exit 2; fi; \
	serving=; \
	if [[ "$@" = cpu-serving ]]; then \
	    if [[ "$(PROFILE)" != inference ]]; then echo 'CPU serving requires PROFILE=inference.' >&2; exit 2; fi; \
	    serving=--cpu-serving; \
	fi; \
	if [[ "$@" = agent-isolation ]]; then \
	    if [[ "$(PROFILE)" != agent ]]; then echo 'Agent isolation requires PROFILE=agent.' >&2; exit 2; fi; \
	    serving=--agent-isolation; \
	fi; \
	$(cleanup_test_images) \
	docker build --build-arg "BUILDER=$(OUTERSPACE_BUILDER)" -t outerspace-enrollment:dev -f tests/Dockerfile .; \
	$(PYTHON) tests/harness/enrollment.py --profile "$(PROFILE)" $${serving:+"$$serving"} --output "$(OUT_DIR)/$$directory"

agent-admission:
	@set -euo pipefail; \
	$(cleanup_test_images) \
	$(PYTHON) tests/harness/enrollment.py --profile agent --agent-admission-only --output "$(OUT_DIR)/agent-admission"
