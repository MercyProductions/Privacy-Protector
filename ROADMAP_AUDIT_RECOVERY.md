# Audit and Recovery Roadmap

This roadmap focuses on making every run easier to review, recover from, and support without adding stealth or bypass behavior.

## Phase 1 - Structured Audit Output

- Generate JSON reports alongside existing text reports.
- Add a no-admin history viewer for recent run outcomes.
- Include dry-run state and timestamps in machine-readable artifacts.
- Keep reports local and transparent.

## Phase 2 - Backup Integrity

- Add backup manifests with file names, timestamps, and hashes.
- Add a backup preview command before restore.
- Add restore result reporting with partial-failure details.
- Add warnings when backups are missing fields.

## Phase 3 - History Tools

- Add filtering by status, computer name, and date.
- Add export to CSV or JSON.
- Add log rotation for large history files.
- Add a support summary that redacts sensitive identifiers.

## Phase 4 - Plan Review

- Add a generated plan file that can be reviewed before apply.
- Add an apply-from-plan workflow.
- Add validation before any plan can be applied.
- Preserve the plan, report, and backup relationship in the audit trail.

## Guardrails

- Do not remove or hide audit artifacts.
- Do not add anti-forensics behavior.
- Do not make cleanup actions implicit.
