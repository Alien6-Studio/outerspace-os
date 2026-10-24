# Image assembly and candidate packaging. Generated files belong in out/.
.PHONY: builder build package config-drive

builder:
	docker build -t "$(OUTERSPACE_BUILDER)" -f build/Dockerfile .

build:
	PYTHON="$(PYTHON)" ./build/build.sh "$(PROFILE)" "$(HARDWARE)"

package:
	@set -euo pipefail; \
	directory=$$($(PYTHON) build/tools/profiles.py directory --profile "$(PROFILE)" --hardware "$(HARDWARE)"); \
	if [[ -n $$(git status --porcelain --untracked-files=normal) ]]; then \
	    echo 'Commit the source before packaging a candidate.' >&2; exit 1; \
	fi; \
	commit=$$(git rev-parse HEAD); \
	docker run --rm --cap-drop=ALL --user "$$(id -u):$$(id -g)" \
	    --mount "type=bind,src=$(CURDIR),dst=/work,readonly" \
	    --mount "type=bind,src=$(OUT_DIR)/$$directory,dst=/out" \
	    "$(OUTERSPACE_BUILDER)" python3 /work/build/tools/package.py \
	    --commit "$$commit" --profile "$(PROFILE)" --hardware "$(HARDWARE)"

config-drive:
	@set -euo pipefail; \
	config_dir=$$(cd "$(CONFIG_DIR)" && pwd); \
	mkdir -p "$(OUT_DIR)"; \
	docker run --rm --cap-drop=ALL \
	    --mount "type=bind,src=$$config_dir,dst=/config,readonly" \
	    --mount "type=bind,src=$(OUT_DIR),dst=/out" \
	    "$(OUTERSPACE_BUILDER)" \
	    bash -euc 'umask 077; test ! -e /out/node-config.raw; truncate -s 16M /out/node-config.raw; mkfs.vfat -n OOS_CONFIG /out/node-config.raw; mcopy -s -i /out/node-config.raw /config/* ::/'
