SHELL := /bin/bash
.DEFAULT_GOAL := help

PROFILE ?=
HARDWARE ?= cpu
PYTHON ?= python3
OUTERSPACE_BUILDER ?= outerspace-builder:dev
OUT_DIR := $(CURDIR)/out
CONFIG_DIR ?= $(OUT_DIR)/node-config

include build/targets.mk
include tests/targets.mk

.PHONY: local-awake
local-awake:
	@if [ "$$(uname -s)" = Darwin ]; then /usr/bin/caffeinate -i -w "$$PPID" >/dev/null 2>&1 & fi

# Keep local VMs and their certificate timers running while make owns the job.
# The assertion ends with make; Linux runners require no power-management change.
builder build package smoke smoke-split enrollment cpu-serving agent-isolation agent-resources \
agent-admission agent-phases worker-comparison serving-comparison serving-admission: | local-awake

.PHONY: help
help:
	@echo 'make check                                      Run unit and syntax checks'
	@echo 'make PROFILE=agent builder build smoke package   Build and qualify an image'
	@echo 'make PROFILE=inference enrollment                Qualify Kubernetes enrollment'
	@echo 'make PROFILE=inference cpu-serving               Qualify real CPU model serving'
	@echo 'make agent-admission                             Preflight Agent admission on a disposable API'
	@echo 'make PROFILE=agent agent-isolation               Qualify the native OCI Agent boundary'
	@echo 'make PROFILE=agent agent-resources               Qualify Agent resource pressure and teardown'
	@echo 'make worker-comparison IMAGE_OUTPUT=out/agent-cpu-ARCH  Compare Agent density with Ubuntu'
	@echo 'make clean-test-cache                            Remove obsolete OuterSpace Docker images'
	@echo 'make config-drive CONFIG_DIR=out/node-config      Package worker configuration'
	@echo 'Generated images, reports and release assets: out/'
