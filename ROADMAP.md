# SUS.NOT — Development Roadmap

## Project Goal

Develop and evaluate a privacy-first AI security guardian
with URL analysis, phishing detection, MCP integration,
email investigation, and browser protection.

## Completed or Previously Implemented

The following components were implemented during earlier
development sessions. Their current status should be
verified against the repository and test results.

- [x] FastAPI backend foundation
- [x] Deterministic URL risk assessment
- [x] Local Ollama text analysis
- [x] MCP SDK integration
- [x] Email MIME investigation
- [x] Explainable evidence generation
- [x] Email redaction and advisory policy
- [x] Initial Chrome extension
- [x] Streamlit dashboard
- [x] Gmail integration security foundation
- [x] Gmail mocked OAuth and connector tests
- [x] macOS Keychain security checks
- [x] Gmail live-readiness documentation
- [x] Private GitHub repository and initial backup

## Next Milestone

### Task 13.3C-2 — Controlled Live Gmail Integration

Status: NOT YET VERIFIED COMPLETE

Objectives:

1. Review existing Gmail integration implementation.
2. Review docs/gmail-live-setup.md.
3. Confirm secure OAuth configuration.
4. Use only an explicitly authorized test account.
5. Test access to one selected synthetic email.
6. Confirm redaction and privacy controls.
7. Verify disconnect and authorization revocation.
8. Run relevant tests.
9. Document results without exposing private data.

Do not access a real account or create credentials
without explicit user approval.

## Future Milestones

### Task 14 — Advanced Detection

- Improve phishing and social-engineering detection.
- Evaluate false positives and false negatives.
- Maintain explainable results.

### Task 15 — Browser Guardian Improvements

- Improve browser protection and usability.
- Maintain opt-in permissions.
- Avoid unnecessary browsing-data collection.

### Task 16 — Dashboard Integration

- Improve integration across existing components.
- Present evidence and risk explanations clearly.
- Maintain privacy-first defaults.

### Task 17 — Security and Reliability

- Review error handling.
- Review secrets management.
- Improve automated tests.
- Validate secure configuration and data retention.

### Task 18 — Academic Evaluation

- Create or verify labeled evaluation cases.
- Report false positives and false negatives.
- Benchmark relevant workflows.
- Record methodology and reproducible evidence.
- Prepare university demonstration material.

## Development Workflow

For each task:

1. Inspect existing implementation.
2. Identify the smallest required change.
3. Explain the proposed approach.
4. Implement only the approved scope.
5. Run relevant tests.
6. Record the results.
7. Update this roadmap.
8. Commit and push after reviewing changes.

## Important

Do not mark a task complete solely because an AI
assistant claims it is complete.

Completion requires evidence from code, tests,
documentation, or a demonstrated working feature.
