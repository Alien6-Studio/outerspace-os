---
title: Frequently asked questions
description: Answers about bare-metal installation, AKS compatibility, P2P storage, GPU support and OuterSpace OS release status.
---
# Questions about OuterSpace OS

## Is this a container image?

It is an operating-system disk image, assembled from Ubuntu packages. Containers
are the workloads it hosts. The first image targets worker nodes.

## Can it replace the OS in an AKS node pool?

No. Managed AKS requires its supported node images. OuterSpace can be tested on
Azure VMs in self-managed Kubernetes, while portable applications can also run on AKS.

## Does P2P eliminate images on every machine?

Each node still needs the layers it executes. Dragonfly can reduce repeated origin
traffic by sharing content between peers. Model-weight storage remains separate.

## When are unused images removed?

Kubelet owns runtime GC with a configured 24-hour maximum unused age and 80%/65%
disk-pressure thresholds. Age tracking resets when kubelet restarts. Dragonfly's
peer cache uses a separate six-hour TTL. These policies still need lifecycle tests.

## Is GPU inference supported?

A GPU profile is planned. Driver/kernel compatibility, signed modules, CDI and a
real inference test on hardware must be validated before claiming support.

## Is it production ready or CIS certified?

No. It is a development foundation with explicit [qualification gates](releases.md).
There is no stable release or completed CIS audit.

## Is it a Flatcar fork?

No. It takes inspiration from the small, immutable container-host approach and
assembles its own image from Ubuntu packages.
