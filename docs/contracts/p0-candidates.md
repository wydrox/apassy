# P0 service candidates

Date: 2026-09-16
Status: PROPOSED

These contracts are synthetic candidates for P0.
They are not confirmed services. They are not live credentials.
The MVP plan names a reporting API and PostgreSQL as candidates, not fixed choices.

Machine-readable copy: `tests/fixtures/p0-services.json`.

## 1. Required shape

A useful API or database candidate must name all of the following:

- Credential type
- Owner-registered destination identity
- Named read operations
- Typed parameters
- Least-privilege requirements
- Bounded output fields and size limits

The connector must refuse arbitrary URLs, raw headers, raw SQL from the agent, and unbounded result sets.
An HTTP GET method or a SELECT prefix is not proof of safety.

Remote verification is still required for provider access, grants, operation semantics, TLS identity, privacy terms, region, limits, and cost.
This document does not invent those facts.

## 2. Synthetic identities

These names are fixtures. They are not accounts, emails, or tokens.

- Owner: `synthetic-owner`
- Reporting agent: `synthetic-reporting-agent`
- Query agent: `synthetic-query-agent`
- Project: `project-a-synthetic`
- Environment label: `staging`

Hostnames use the reserved `example.invalid` suffix.

## 3. Candidate A — reporting API

- Candidate of: reporting API in the MVP plan
- Kind: HTTP API
- Credential type: API key
- Display name: Project A reporting service
- Hostname: `reporting.example.invalid`
- Scheme: `https`
- Environment: `staging`

Least-privilege requirement: a read-only reporting grant for Project A staging only.
Forbidden: production hosts, arbitrary URLs, write operations, and agent-controlled headers.
Provider grants are unverified.

### Named read operations

`get_sales_summary`

- Parameters:
  - `project_id` (string, required): must equal `project-a-synthetic`
  - `period_start` (string, required): date `YYYY-MM-DD`
  - `period_end` (string, required): date `YYYY-MM-DD`
- Output: one record with `project_id`, `period_start`, `period_end`, `currency`, `total_amount`, `order_count`
- Output limits: one record. No credentials. No raw HTTP bodies. No other projects.

`get_report_job_status`

- Parameters:
  - `job_id` (string, required): must match a job for `project-a-synthetic`
- Output: one record with `job_id`, `state`, `completed_at`
- Output limits: one record. No credentials. No raw logs.

## 4. Candidate B — staging database

- Candidate of: PostgreSQL in the MVP plan
- Kind: SQL database
- Engine candidate: PostgreSQL
- Credential type: database credential
- Display name: Project A staging database
- Hostname: `db.staging.example.invalid`
- Port candidate: `5432`
- Database name: `project_a_staging_synthetic`
- Environment: `staging`

Least-privilege requirement: a read-only role with `SELECT` on named views only.
Forbidden: production hosts, superuser rights, writes, raw SQL from the agent, and COPY of whole tables.
Provider grants are unverified. The engine choice is not fixed.

### Named read operations

`read_sales_summary`

- Object: `view_sales_summary_synthetic`
- Parameters:
  - `project_id` (string, required): must equal `project-a-synthetic`
  - `period_start` (string, required): date `YYYY-MM-DD`
  - `period_end` (string, required): date `YYYY-MM-DD`
- Output fields: `project_id`, `day`, `currency`, `total_amount`, `order_count`
- Output limits: 31 rows. No credentials. No full table dumps.

`read_daily_order_counts`

- Object: `view_daily_order_counts_synthetic`
- Parameters:
  - `project_id` (string, required): must equal `project-a-synthetic`
  - `day` (string, required): date `YYYY-MM-DD`
- Output fields: `project_id`, `day`, `order_count`
- Output limits: one row. No credentials. No other days.

## 5. Unverified items

These candidates do not establish:

- Live API or database access
- Real grants, roles, or privacy terms
- Verified operation semantics
- Production or staging destinations that exist outside this fixture

Model contracts for Jev and the rule interpreter remain unverified.
That gap blocks live P5 and P6 work. It does not block this synthetic contract.

P0 is not complete. These candidates do not freeze P4.
