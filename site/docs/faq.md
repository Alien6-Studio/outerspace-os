---
title: Frequently asked questions
description: Answers about the CPU alpha, Agent and Inference profiles, image verification, GPU support and release status.
---
# Questions about OuterSpace OS

## What is available now?

`0.1.0-alpha.1` has four qualified CPU images: Agent and Inference on AMD64 and
ARM64. The first milestone is complete and the release is prepared as a draft.
Public downloads will appear on [GitHub Releases](https://github.com/Alien6-Studio/outerspace-os/releases)
after publication. There is no stable release.

## Is this a container image?

It is an operating-system disk image for Kubernetes workers. Containers hold the
Agent or Inference workloads. Both profiles share one immutable Core, but each
shipped image is qualified separately.

## Does the alpha run a real model?

Yes. The Inference candidates passed a separately pinned CPU serving workload,
including replacement, drain and recovery after node restart. The model weights
and serving container are not bundled into the host or covered by its licenses.

## Does an attestation enable Secure Boot?

No. The GitHub attestation authenticates the checksum inventory and its build
provenance. Secure Boot and authenticated A/B updates have separate, unfinished
gates. The alpha uses UEFI with Secure Boot disabled.

## Is GPU or bare-metal operation supported?

Neither has a qualified hardware matrix yet. Evaluate this alpha in disposable
UEFI VMs. Driver/kernel/CDI integration and physical hardware tests are later work.

## Does Dragonfly eliminate local image storage?

Each node still needs the image layers it executes. Optional peer delivery can
share OCI content, while model-weight storage remains separate. P2P, private
registry authorization and fleet cache lifecycle are not yet qualified.

## Is it production ready or CIS certified?

No. This is an experimental CPU alpha with explicit [limits and release gates](releases.md).
In particular, the [time-limited kernel risk acceptance](security.md) excludes
host VPNs and custom networking.

## Is it a Flatcar fork?

No. OuterSpace maintains its own Ubuntu-based image and source-built kernel/runtime
inputs, with independently packaged Agent and Inference profiles.
