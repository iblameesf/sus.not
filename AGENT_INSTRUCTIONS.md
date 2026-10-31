# SUS.NOT — AI Agent Instructions

You are assisting with the existing SUS.NOT university project.

Your role is to continue development safely and incrementally.

## Mandatory Startup Procedure

Before suggesting code changes:

1. Read PROJECT_CONTEXT.md.
2. Read ROADMAP.md.
3. Inspect the repository structure.
4. Read documentation relevant to the requested task.
5. Check git status.
6. Identify the current milestone.
7. Verify whether the requested feature already exists.

Never assume this is a new project.

## Development Rules

- Preserve existing architecture.
- Prefer minimal, targeted changes.
- Reuse existing modules and patterns.
- Avoid unnecessary dependencies.
- Do not rewrite unrelated components.
- Do not modify files without a clear reason.
- Explain significant design decisions.
- Keep changes testable and reversible.

## Privacy and Security

Never:

- Request that the user paste passwords or API tokens.
- Print authentication secrets into chat or logs.
- Commit OAuth credentials.
- Commit Gmail access or refresh tokens.
- Upload private email contents without authorization.
- Enable external integrations without explicit consent.
- Claim that heuristic risk scores are fraud probabilities.

For Gmail integration:

- Prefer a dedicated test account.
- Use synthetic test emails.
- Follow least-privilege access.
- Maintain secure local credential storage.
- Verify disconnect and revocation.
- Avoid unnecessary data retention.

## Working With Limited AI Usage

The user may switch between ChatGPT accounts,
Pi, and other AI coding assistants.

Therefore:

- Work on one small task at a time.
- Do not rely on previous chat history.
- Read project documentation for context.
- Provide concise implementation plans.
- Avoid unnecessarily large prompts.
- Record important decisions in repository documentation.
- Clearly state what was and was not completed.

## Required Response Format

For development tasks, use:

1. Current understanding
2. Proposed next step
3. Files affected
4. Commands or changes
5. Verification
6. Remaining work

If the user asks for one step only, provide one step only.

## Git Rules

Before changing code:

git status

After making changes:

- Review git diff.
- Run relevant tests.
- Stage only intended files.
- Commit with a descriptive message.
- Push only after reviewing the staged changes.

Never use destructive Git commands without
explaining their consequences and obtaining approval.

Never commit secrets.

## Academic Integrity

- Distinguish implemented features from planned features.
- Distinguish synthetic tests from live tests.
- Report evaluation limitations.
- Do not fabricate benchmarks or test results.
- Preserve reproducibility and evidence.

## Current Development Target

Task 13.3C-2 — Controlled Live Gmail Integration.

Before implementation, inspect:

docs/gmail-live-setup.md

Also inspect the actual Gmail connector, OAuth,
token-storage, readiness, and test modules.

Do not begin live authorization without user approval.

## First Response in a New Session

After inspecting the project, summarize:

- What exists.
- What is verified.
- What remains.
- The single next recommended action.

Do not immediately rewrite the project.
