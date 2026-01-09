# endor-ignore-file-custom

A simple Node.js project designed to exercise vulnerability scanners such as Endor Labs.

## Overview

This project intentionally includes a dependency with known security vulnerabilities to test and demonstrate vulnerability scanning capabilities.

## Vulnerable Dependency

- **Package**: lodash
- **Version**: 4.17.19
- **Known Vulnerabilities**:
  - CVE-2020-8203 (Prototype Pollution) - CVSS 7.4 (High)
  - CVE-2019-10744 (Regular Expression Denial of Service) - CVSS 5.3 (Moderate)
  - Command Injection - CVSS 7.2 (High)
- **Category**: String manipulation and object merging

The vulnerable code paths are exercised through various lodash functions including:
- `_.merge()` - Object merging
- `_.mergeWith()` - Custom object merging
- `_.set()` - Setting nested object properties with string paths
- `_.template()` - String templating
- String manipulation utilities (trim, upperCase, camelCase)

## Installation

```bash
npm install
```

## Usage

Run the application to exercise the vulnerable dependency:

```bash
npm start
```

Or:

```bash
node index.js
```

## Expected Output

The application demonstrates various uses of the vulnerable lodash library, including string manipulation and object operations that could be exploited for prototype pollution attacks.

## Endor Labs Integration

This repository includes automated Endor Labs exception policy management via GitHub Actions.

### Ignore File

The `.endorignore` file contains vulnerability IDs that should be ignored by Endor Labs scans. Format:
- One vulnerability ID per line
- Comments start with `#`
- Blank lines are ignored

Example:
```
# Ignore Regular Expression Denial of Service (ReDoS) in lodash
GHSA-35jh-r3h4-6jhm
GHSA-29mw-wpgm-hmr9
```

### GitHub Actions Workflows

Three workflows are configured:

1. **`endor-sync.yml`** - Runs on PR open/sync/reopen
   - Syncs PR-specific exception policy from `.endorignore`
   - Runs Endor scan with PR comments enabled

2. **`endor-main-sync.yml`** - Runs on push to main/master
   - Syncs main branch exception policy from `.endorignore`

3. **`endor-pr-cleanup.yml`** - Runs on PR close
   - Deletes PR-specific exception policy

### Required GitHub Secrets

Configure these secrets in your repository settings:

- `ENDOR_NAMESPACE` - Your Endor namespace (e.g., `leonardo-learn`)
- `ENDOR_API_KEY` - Endor API key
- `ENDOR_API_SECRET` - Endor API secret

The `GITHUB_TOKEN` is automatically provided by GitHub Actions and has PR read/write permissions.

### Manual Script Usage

You can also run the sync script manually:

```bash
# Sync main branch policy
python scripts/sync_endor_policy.py \
  --namespace <namespace> \
  --repo-url "git@github.com:org/repo.git"

# Sync PR policy
python scripts/sync_endor_policy.py \
  --namespace <namespace> \
  --repo-url "git@github.com:org/repo.git" \
  --pr-id <pr_number>

# Cleanup PR policy
python scripts/sync_endor_policy.py \
  --namespace <namespace> \
  --repo-url "git@github.com:org/repo.git" \
  --pr-id <pr_number> \
  --cleanup
```

## Security Warning

⚠️ **This project is for testing purposes only!** 

The included vulnerable dependency (lodash 4.17.19) has known security issues and should not be used in production environments. This project is specifically designed to help test vulnerability scanning tools.

## License

MIT