# Cerberus Demo Surface Strategy

This document defines how Cerberus should present demos without confusing the
public Core wedge.

## Canonical Split

Cerberus uses two demo surfaces:

1. **Core Live Attack Demo**
2. **Analyst Playground**

They are related, but they do different jobs.

## Core Live Attack Demo

Primary public surface:

- GitHub README
- GitHub About homepage
- npm
- PyPI
- public docs

Primary URL:

- `https://odingard.github.io/cerberus-core/`

Purpose:

- pull developers and buyers into the Core product quickly
- prove the runtime control point in under 30 seconds
- show the exact moment `guard()` interrupts a guarded outbound action

Required characteristics:

- interactive
- attack-driven
- visually live
- one canonical proof path
- easy to explain without an operator present

What it should show:

- trusted data access
- untrusted content ingestion
- outbound action attempt
- L1 / L2 / L3 accumulation
- interrupt before executor run
- minimal installation path

What it should not become:

- multi-team monitoring tour
- enterprise operations console
- generalized observability dashboard
- broad product walkthrough

## Analyst Playground

Secondary field/demo surface:

- hosted analyst sessions
- deeper customer walkthroughs
- dashboard-linked storytelling
- richer scenario exploration

Current URL:

- `https://demo.cerberus.sixsenseenterprise.com`

Purpose:

- extend conviction after the Core proof lands
- show multiple scenarios and richer runtime context
- support analyst, partner, and enterprise conversations

What it can include:

- multiple scenarios
- dashboard links
- enterprise simulation
- richer evidence strip
- deeper runtime narrative

What it should not do:

- replace the Core wedge on public package surfaces
- compete with the public Core demo for first impression

## Labeling Rules

The labels must stay consistent:

- public repo / package surfaces:
  - `Core Live Attack Demo`
- hosted field surface:
  - `Analyst Playground`

Do not use `Live Demo` generically across both surfaces.

## Funnel Order

The intended order is:

1. Core Live Attack Demo
2. install / docs
3. Analyst Playground
4. dashboard / enterprise conversation

## Product Message

The public message is:

`Cerberus Core is the embeddable runtime enforcement layer.`

The hosted playground message is:

`This is the deeper analyst environment built on top of the same Core runtime story.`

## Implementation Guidance

Public Core repo:

- keep the Core demo as the canonical public proof path
- embed proof media in README
- keep Pages demo easy to access

Hosted analyst surface:

- add a visible label that it is the analyst playground
- link back to the public Core demo
- preserve the deeper scenario and dashboard story

