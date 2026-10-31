# SUS.NOT — Project Context

## 1. Project Overview

SUS.NOT is a university AI and cybersecurity project.

Its objective is to provide a privacy-first digital security
guardian that helps users identify suspicious URLs, phishing
messages, and social-engineering attempts.

The system combines deterministic security checks, local AI
analysis, and Model Context Protocol (MCP) tools.

## 2. Core Principles

- Privacy first.
- Local processing wherever practical.
- Explainable security findings.
- User consent before accessing external accounts.
- Advisory warnings rather than automatic blocking.
- No unnecessary collection or retention of personal data.
- No credentials or authentication tokens in Git.

## 3. Development Environment

Primary development machine:
- MacBook Air M3
- 8 GB RAM
- macOS

Technologies:
- Python 3.12
- FastAPI
- Streamlit
- Ollama
- Local Qwen model
- Model Context Protocol (MCP)
- Chrome Manifest V3 extension
- Git and GitHub

## 4. Existing Components

### Backend

FastAPI application with endpoints including:

- /health
- /analyze-url
- /analyze-text
- /evaluate-url
- /investigate
- /investigate-email

### URL Guardian

Deterministic URL analysis with explainable indicators.

Examples:
- IP-address hostnames
- Suspicious URL authority patterns
- Urgency-related URL paths

Scores are heuristic risk indicators, not probabilities
that a website is malicious.

### AI Guardian

Local LLM-based analysis of suspicious messages.

Uses Ollama and a Qwen model to identify potential
phishing and social-engineering indicators.

### MCP Integration

MCP tools for URL and text inspection.

The project uses the MCP SDK rather than treating MCP
as a simple naming convention.

### Email Guardian

Email investigation capabilities include:

- MIME email parsing
- Sender and Reply-To comparison
- Suspicious URL detection
- Explainable evidence
- Redaction of sensitive information
- Advisory risk recommendations

### Browser Guardian

Chrome Manifest V3 extension with opt-in protection
and warning overlays.

### Dashboard

Streamlit interface for interacting with the system.

### Gmail Integration

Security foundation and readiness checks have been
implemented.

Live Gmail integration testing is the next planned task.

## 5. Git Repository

Repository:
https://github.com/iblameesf/sus.not

Visibility:
Private

Primary branch:
main

Local directory:
~/Projects/sus-not

GitHub is the source of truth for committed code.

## 6. Important Constraints

- Preserve the existing architecture.
- Inspect the repository before changing code.
- Do not recreate existing features unnecessarily.
- Do not introduce new dependencies without justification.
- Do not expose real Gmail messages or authentication tokens.
- Do not commit .env files, OAuth credentials, or access tokens.
- Keep security decisions explainable.
- Maintain backward compatibility where practical.
- Test changes before committing.

## 7. Project Status

The project has been committed locally and pushed to
the private GitHub repository.

The next planned milestone is:

Task 13.3C-2 — Controlled Live Gmail Integration.

Before implementing it, inspect the actual code and
docs/gmail-live-setup.md to verify readiness.

## 8. Source of Truth

This document is a handover summary.

The actual repository, tests, API schemas, and existing
documentation take precedence over this summary.

If documentation and implementation disagree, report
the discrepancy instead of assuming either is correct.
