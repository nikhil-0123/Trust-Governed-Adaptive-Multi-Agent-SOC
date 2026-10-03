---
trigger: always_on
---

TWO-REPOSITORY WORKSPACE RULE

This Antigravity workspace contains TWO separate repositories.

REPOSITORY 1 — ACTUAL SOURCE CODE

P:\Trust-Governed-Adaptive-Multi-Agent-SOC

This is the ONLY repository where implementation code may normally be created or modified.

Allowed activities:

- Create source code
- Modify source code
- Create tests
- Modify tests
- Create runtime configuration
- Run project commands
- Run tests
- Debug implementation
- Update implementation documentation
- Perform Git operations when explicitly instructed

REPOSITORY 2 — PROJECT KNOWLEDGE

P:\TGAM-SOC-knowledge

This repository contains:

- Architecture
- Authoritative project documents
- Research papers
- Planning
- Presentations
- PROJECT_STATUS.md
- Project reference material

Treat this repository as READ-ONLY during implementation.

DO NOT:

- Modify research papers
- Modify the Synopsis
- Modify the Design Paper
- Modify architecture documents
- Modify PROJECT_STATUS.md
- Delete knowledge files
- Rename knowledge files
- Add generated implementation files
- Commit implementation code into this repository

unless the project owner explicitly instructs you to modify a specific knowledge file.

==================================================
READ / WRITE POLICY
==================================================

P:\TGAM-SOC-knowledge
        ↓
READ / REFERENCE

P:\Trust-Governed-Adaptive-Multi-Agent-SOC
        ↓
IMPLEMENT / TEST / DEBUG

Never confuse the two repositories.

If you are unsure which repository a file belongs to:

STOP and ask before modifying it.

==================================================
PROJECT KNOWLEDGE AUTHORITY
==================================================

Use:

P:\TGAM-SOC-knowledge

to understand:

- Project requirements
- Approved architecture
- Research
- Design
- Planning
- Current project status

Use:

P:\Trust-Governed-Adaptive-Multi-Agent-SOC

for:

- Implementation
- Testing
- Runtime configuration
- Debugging
- Source-code changes

Never use the knowledge repository as a substitute for the actual source-code repository.