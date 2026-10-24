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

.PHONY: help
help:
	@echo 'make check                                      Run unit and syntax checks'
	@echo 'make PROFILE=agent builder build smoke package   Build and qualify an image'
	@echo 'make PROFILE=inference enrollment                Qualify Kubernetes enrollment'
	@echo 'make PROFILE=inference cpu-serving               Qualify real CPU model serving'
	@echo 'make agent-admission                             Preflight Agent admission on a disposable API'
	@echo 'make PROFILE=agent agent-isolation               Qualify the native OCI Agent boundary'
	@echo 'make clean-test-cache                            Remove obsolete OuterSpace Docker images'
	@echo 'make config-drive CONFIG_DIR=out/node-config      Package worker configuration'
	@echo 'Generated images, reports and release assets: out/'
