# Local and CI qualification; none of these tools are installed in the OS.
.PHONY: check smoke smoke-split enrollment cpu-serving agent-isolation agent-resources agent-admission agent-phases worker-comparison serving-comparison serving-admission clean-test-cache
IMAGE_OUTPUT ?= $(OUT_DIR)/$(shell $(PYTHON) build/tools/profiles.py directory --profile agent --hardware cpu)
SERVING_IMAGE_OUTPUT ?= $(OUT_DIR)/$(shell $(PYTHON) build/tools/profiles.py directory --profile inference --hardware cpu)
REFERENCE_CACHE ?= $(CURDIR)/.cache/ubuntu-reference
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

enrollment cpu-serving agent-isolation agent-resources:
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
	if [[ "$@" = agent-resources ]]; then \
	    if [[ "$(PROFILE)" != agent ]]; then echo 'Agent resources requires PROFILE=agent.' >&2; exit 2; fi; \
	    serving=--agent-resources; \
	fi; \
	$(cleanup_test_images) \
	docker build --build-arg "BUILDER=$(OUTERSPACE_BUILDER)" -t outerspace-enrollment:dev -f tests/Dockerfile .; \
	$(PYTHON) tests/harness/enrollment.py --profile "$(PROFILE)" $${serving:+"$$serving"} --output "$(OUT_DIR)/$$directory"

agent-admission:
	@set -euo pipefail; \
	$(cleanup_test_images) \
	$(PYTHON) tests/harness/enrollment.py --profile agent --agent-admission-only --output "$(OUT_DIR)/agent-admission"

# Compare an immutable, already packaged Agent candidate; results bind its commit
# separately from the comparison harness commit. No extra shipping OS profile.
worker-comparison:
	@set -euo pipefail; \
	$(cleanup_test_images) \
	docker build --build-arg "BUILDER=$(OUTERSPACE_BUILDER)" -t outerspace-enrollment:dev -f tests/Dockerfile .; \
	$(PYTHON) tests/harness/worker-comparison.py --image-output "$(IMAGE_OUTPUT)" \
	    --output "$(OUT_DIR)/worker-comparison" --cache "$(REFERENCE_CACHE)"

# Compare phase collection with an unprofiled execution of the same immutable
# Agent candidate. The Python gateway and observer are lab workloads, not host services.
agent-phases:
	@set -euo pipefail; \
	$(cleanup_test_images) \
	docker build --build-arg "BUILDER=$(OUTERSPACE_BUILDER)" -t outerspace-enrollment:dev -f tests/Dockerfile .; \
	$(PYTHON) tests/harness/agent-phase-benchmark.py --image-output "$(IMAGE_OUTPUT)" \
	    --output "$(OUT_DIR)/agent-phases"

serving-admission:
	$(PYTHON) tests/harness/serving-comparison.py --admission-only --output "$(OUT_DIR)/serving-admission"

serving-comparison:
	@set -euo pipefail; \
	$(cleanup_test_images) \
	docker build --build-arg "BUILDER=$(OUTERSPACE_BUILDER)" -t outerspace-enrollment:dev -f tests/Dockerfile .; \
	$(PYTHON) tests/harness/serving-comparison.py --image-output "$(SERVING_IMAGE_OUTPUT)" \
	    --output "$(OUT_DIR)/serving-comparison" --cache "$(REFERENCE_CACHE)"
