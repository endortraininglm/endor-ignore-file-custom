# Endor Labs Exception Policy Sync Script

This script (`sync_endor_policy.py`) syncs vulnerability IDs from `.endorignore` file to Endor Labs exception policies. It supports both main branch policies and PR-specific policies.

## Overview

The script automatically manages Endor Labs exception policies based on the contents of a `.endorignore` file in your repository. It can:
- Create or update main branch exception policies
- Create or update PR-specific exception policies
- Delete PR-specific policies when PRs are closed
- Compare existing policies with desired state and only update when needed

## Ignore File Format

The `.endorignore` file contains vulnerability IDs that should be ignored by Endor Labs scans. Format:
- One vulnerability ID per line
- Comments start with `#`
- Blank lines are ignored

Example:
```
# Ignore Regular Expression Denial of Service (ReDoS) in lodash
GHSA-35jh-r3h4-6jhm
GHSA-29mw-wpgm-hmr9
CVE-2020-8203
```

## Usage

### Sync Main Branch Policy

Syncs the main branch exception policy from `.endorignore`:

```bash
python scripts/sync_endor_policy.py \
  --namespace <namespace> \
  --repo-url "git@github.com:org/repo.git" \
  --api-key <api_key> \
  --api-secret <api_secret>
```

### Sync PR Policy

Syncs a PR-specific exception policy from `.endorignore`:

```bash
python scripts/sync_endor_policy.py \
  --namespace <namespace> \
  --repo-url "git@github.com:org/repo.git" \
  --pr-id <pr_number> \
  --api-key <api_key> \
  --api-secret <api_secret>
```

### Cleanup PR Policy

Deletes a PR-specific exception policy (typically called when a PR is closed):

```bash
python scripts/sync_endor_policy.py \
  --namespace <namespace> \
  --repo-url "git@github.com:org/repo.git" \
  --pr-id <pr_number> \
  --cleanup \
  --api-key <api_key> \
  --api-secret <api_secret>
```

## Command-Line Arguments

- `--namespace` (required): Endor namespace (e.g., `leonardo-learn`)
- `--repo-url` (required): Git repository URL (e.g., `git@github.com:org/repo.git`)
- `--pr-id` (optional): PR ID (if provided, syncs PR-specific policy; otherwise syncs main policy)
- `--ignore-file` (optional): Path to ignore file (default: `.endorignore`)
- `--cleanup` (optional): Delete PR policy (use with `--pr-id` for PR cleanup)
- `--api-key` (optional): Endor API key (or set `ENDOR_API_KEY` env var)
- `--api-secret` (optional): Endor API secret (or set `ENDOR_API_SECRET` env var)

## Environment Variables

Instead of passing API credentials via command-line arguments, you can set:
- `ENDOR_API_KEY`: Endor API key
- `ENDOR_API_SECRET`: Endor API secret

## Policy Tag Convention

The script uses the following tag conventions for policies:
- Main policy: `project-{project_uuid}-main`
- PR policy: `project-{project_uuid}-pr-{pr_id}`

Where `project_uuid` is the Endor project UUID derived from the repository URL.

## How It Works

1. **Parse `.endorignore`**: Reads and extracts vulnerability IDs (ignoring comments and blank lines)
2. **Get Project UUID**: Looks up the Endor project UUID from the repository URL
3. **Find Existing Policy**: Searches for an existing policy by tag
4. **Compare**: Extracts vulnerability IDs from the existing policy's Rego rule and compares with desired state
5. **Create or Update**: Only creates or updates the policy if the vulnerability IDs differ
6. **Generate Rego Rules**: Generates appropriate Rego rules for main branch or PR contexts

## GitHub Actions Integration

This script is designed to be used in GitHub Actions workflows. See the main repository README for workflow configuration details.

## Error Handling

- If the ignore file is not present, the script exits gracefully (unless in cleanup mode)
- If the project is not found, the script exits with an error
- If policy operations fail, appropriate error messages are displayed
- The script writes the project UUID to `.endor-project-uuid` for use in subsequent workflow steps

