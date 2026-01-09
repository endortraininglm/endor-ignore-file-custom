#!/usr/bin/env python3
"""
Endor Labs Exception Policy Sync Script

This script syncs vulnerability IDs from .endorignore file to Endor Labs exception policies.
It supports both main branch policies and PR-specific policies.

Usage:
    python sync_endor_policy.py --namespace <namespace> --repo-url <repo_url> [--pr-id <pr_id>]
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any


# Rego rule templates
REGO_TEMPLATE_MAIN = """package exceptions

match_vuln_id(finding, ids) {{
  finding.spec.finding_metadata.vulnerability.meta.name = ids[_]
}}

match_vuln_id(finding, ids) {{
  finding.spec.finding_metadata.vulnerability.spec.aliases[_] = ids[_]
}}

match_vuln_id(finding, ids) {{
  finding.spec.finding_metadata.malware.spec.aliases[_] = ids[_]
}}

match_main_branch(finding) {{
  finding.context.type == "CONTEXT_TYPE_MAIN"
}}

match_main_branch(finding) {{
  finding.context.type == "CONTEXT_TYPE_REF"
}}

match_finding[result] {{
  some i
  finding := data.resources.Finding[i]
  ids := {vuln_ids}
 
  match_main_branch(finding)
  match_vuln_id(finding, ids)
  result = {{
    "Endor" : {{
      "Finding" : finding.uuid
    }}
  }}
}}
"""

REGO_TEMPLATE_PR = """package exceptions

match_vuln_id(finding, ids) {{
  finding.spec.finding_metadata.vulnerability.meta.name = ids[_]
}}

match_vuln_id(finding, ids) {{
  finding.spec.finding_metadata.vulnerability.spec.aliases[_] = ids[_]
}}

match_vuln_id(finding, ids) {{
  finding.spec.finding_metadata.malware.spec.aliases[_] = ids[_]
}}

match_pr_branch(finding) {{
  pr_tag := ["scan-{project_uuid}-pr-{pr_id}"]
  finding.context.type == "CONTEXT_TYPE_CI_RUN"
  finding.context.tags[_] = pr_tag[_]
}}

match_finding[result] {{
  some i
  finding := data.resources.Finding[i]
  ids := {vuln_ids}
 
  match_pr_branch(finding)
  match_vuln_id(finding, ids)
  result = {{
    "Endor" : {{
      "Finding" : finding.uuid
    }}
  }}
}}
"""


def run_endorctl_command(namespace: str, command: List[str]) -> Dict[Any, Any]:
    """Run an endorctl command and return parsed JSON output."""
    full_command = ["endorctl", "-n", namespace] + command
    try:
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout.strip():
            return json.loads(result.stdout)
        return {}
    except subprocess.CalledProcessError as e:
        print(f"Error running endorctl command: {' '.join(full_command)}", file=sys.stderr)
        print(f"Error output: {e.stderr}", file=sys.stderr)
        raise
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON output: {e}", file=sys.stderr)
        print(f"Output was: {result.stdout}", file=sys.stderr)
        raise


def parse_ignore_file(ignore_file_path: str = ".endorignore") -> List[str]:
    """
    Parse .endorignore file and extract vulnerability IDs.
    
    Returns:
        Sorted list of vulnerability IDs (excluding comments and blank lines)
    """
    ignore_path = Path(ignore_file_path)
    
    if not ignore_path.exists():
        print(f"Ignore file not present: {ignore_file_path}")
        return []
    
    vuln_ids = []
    with open(ignore_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip comments and blank lines
            if line and not line.startswith('#'):
                vuln_ids.append(line)
    
    return sorted(vuln_ids)


def get_project_uuid(namespace: str, repo_url: str) -> Optional[str]:
    """
    Get Endor project UUID from repository URL.
    
    Args:
        namespace: Endor namespace
        repo_url: Git repository URL (e.g., git@github.com:org/repo.git)
    
    Returns:
        Project UUID or None if not found
    """
    command = [
        "api", "list", "-r", "Project",
        "--filter", f"spec.git.git_clone_url=='{repo_url}'",
        "--field-mask", "uuid"
    ]
    
    result = run_endorctl_command(namespace, command)
    
    objects = result.get("list", {}).get("objects", [])
    if objects:
        return objects[0].get("uuid")
    
    return None


def get_policy_by_tag(namespace: str, tag: str) -> Optional[Dict[Any, Any]]:
    """
    Find exception policy by tag.
    
    Args:
        namespace: Endor namespace
        tag: Policy tag to search for (e.g., "project-{uuid}-main")
    
    Returns:
        Policy object or None if not found
    """
    filter_expr = f'spec.policy_type=="POLICY_TYPE_EXCEPTION" and meta.tags matches "{tag}"'
    command = [
        "api", "list", "-r", "Policy",
        "--filter", filter_expr,
        "--limit", "1"
    ]
    
    result = run_endorctl_command(namespace, command)
    
    objects = result.get("list", {}).get("objects", [])
    if objects:
        return objects[0]
    
    return None


def extract_vuln_ids_from_rego(rego_rule: str) -> List[str]:
    """
    Extract vulnerability IDs from Rego rule.
    
    Looks for the pattern: ids := ["ID1", "ID2", ...]
    
    Returns:
        Sorted list of vulnerability IDs
    """
    # Match: ids := ["ID1", "ID2", ...]
    pattern = r'ids\s*:=\s*\[(.*?)\]'
    match = re.search(pattern, rego_rule, re.DOTALL)
    
    if not match:
        return []
    
    ids_str = match.group(1)
    # Extract quoted strings
    id_pattern = r'"([^"]+)"'
    vuln_ids = re.findall(id_pattern, ids_str)
    
    return sorted(vuln_ids)


def generate_rego_rule(vuln_ids: List[str], project_uuid: str, pr_id: Optional[str] = None) -> str:
    """
    Generate Rego rule for exception policy.
    
    Args:
        vuln_ids: List of vulnerability IDs
        project_uuid: Endor project UUID
        pr_id: PR ID (if None, generates main branch rule)
    
    Returns:
        Rego rule as string
    """
    # Format vulnerability IDs as JSON array string for Rego
    vuln_ids_json = json.dumps(vuln_ids)
    
    if pr_id:
        # PR-specific rule
        return REGO_TEMPLATE_PR.format(
            project_uuid=project_uuid,
            pr_id=pr_id,
            vuln_ids=vuln_ids_json
        )
    else:
        # Main branch rule
        return REGO_TEMPLATE_MAIN.format(vuln_ids=vuln_ids_json)


def create_policy(
    namespace: str,
    project_uuid: str,
    vuln_ids: List[str],
    policy_name: str,
    tag: str,
    pr_id: Optional[str] = None
) -> str:
    """
    Create a new exception policy.
    
    Returns:
        Created policy UUID
    """
    rego_rule = generate_rego_rule(vuln_ids, project_uuid, pr_id)
    
    policy_data = {
        "spec": {
            "exception": {
                "reason": "EXCEPTION_REASON_RISK_ACCEPTED",
                "tags": ["managed-by-repository-rules"]
            },
            "policy_type": "POLICY_TYPE_EXCEPTION",
            "project_selector": [f"$uuid={project_uuid}"],
            "query_statements": ["data.exceptions.match_finding"],
            "resource_kinds": ["Finding"],
            "rule": rego_rule
        },
        "meta": {
            "description": "",
            "name": policy_name,
            "tags": ["managed-by-repository-rules", tag]
        },
        "propagate": True
    }
    
    command = [
        "api", "create", "--resource", "Policy",
        "--data", json.dumps(policy_data)
    ]
    
    result = run_endorctl_command(namespace, command)
    policy_uuid = result.get("uuid")
    
    if not policy_uuid:
        raise ValueError(f"Failed to create policy. Response: {result}")
    
    return policy_uuid


def update_policy(
    namespace: str,
    policy_uuid: str,
    project_uuid: str,
    vuln_ids: List[str],
    policy_name: str,
    tag: str,
    pr_id: Optional[str] = None
) -> None:
    """Update an existing exception policy."""
    rego_rule = generate_rego_rule(vuln_ids, project_uuid, pr_id)
    
    policy_data = {
        "meta": {
            "description": "",
            "name": policy_name,
            "tags": ["managed-by-repository-rules", tag]
        },
        "propagate": True,
        "spec": {
            "rule": rego_rule
        }
    }
    
    command = [
        "api", "update", "-r", "Policy",
        "--uuid", policy_uuid,
        "--field-mask", "spec.rule",
        "--data", json.dumps(policy_data)
    ]
    
    run_endorctl_command(namespace, command)


def delete_policy(namespace: str, policy_uuid: str) -> None:
    """Delete an exception policy."""
    command = [
        "api", "delete", "-r", "Policy",
        "--uuid", policy_uuid
    ]
    
    run_endorctl_command(namespace, command)


def sync_main_policy(
    namespace: str,
    project_uuid: str,
    vuln_ids: List[str],
    repo_name: str
) -> None:
    """
    Sync main branch exception policy.
    
    Creates or updates the policy if vulnerability IDs differ.
    """
    tag = f"project-{project_uuid}-main"
    policy_name = f"Exception Policy For Repo [{repo_name}] - Version: Main"
    
    # Check if policy exists
    existing_policy = get_policy_by_tag(namespace, tag)
    
    if existing_policy:
        # Extract current vulnerability IDs
        current_rego = existing_policy.get("spec", {}).get("rule", "")
        current_vuln_ids = extract_vuln_ids_from_rego(current_rego)
        
        # Compare (both should be sorted)
        if current_vuln_ids == vuln_ids:
            print(f"Main policy already up to date. No changes needed.")
            return
        
        # Update existing policy
        print(f"Updating main policy with {len(vuln_ids)} vulnerability IDs...")
        update_policy(
            namespace,
            existing_policy["uuid"],
            project_uuid,
            vuln_ids,
            policy_name,
            tag
        )
        print(f"Main policy updated successfully.")
    else:
        # Create new policy
        print(f"Creating main policy with {len(vuln_ids)} vulnerability IDs...")
        policy_uuid = create_policy(
            namespace,
            project_uuid,
            vuln_ids,
            policy_name,
            tag
        )
        print(f"Main policy created successfully (UUID: {policy_uuid}).")


def sync_pr_policy(
    namespace: str,
    project_uuid: str,
    vuln_ids: List[str],
    repo_name: str,
    pr_id: str
) -> None:
    """
    Sync PR-specific exception policy.
    
    Creates or updates the policy if vulnerability IDs differ.
    """
    tag = f"project-{project_uuid}-pr-{pr_id}"
    policy_name = f"Exception Policy For Repo [{repo_name}] - Version: PR-{pr_id}"
    
    # Check if policy exists
    existing_policy = get_policy_by_tag(namespace, tag)
    
    if existing_policy:
        # Extract current vulnerability IDs
        current_rego = existing_policy.get("spec", {}).get("rule", "")
        current_vuln_ids = extract_vuln_ids_from_rego(current_rego)
        
        # Compare (both should be sorted)
        if current_vuln_ids == vuln_ids:
            print(f"PR policy already up to date. No changes needed.")
            return
        
        # Update existing policy
        print(f"Updating PR policy with {len(vuln_ids)} vulnerability IDs...")
        update_policy(
            namespace,
            existing_policy["uuid"],
            project_uuid,
            vuln_ids,
            policy_name,
            tag,
            pr_id
        )
        print(f"PR policy updated successfully.")
    else:
        # Create new policy
        print(f"Creating PR policy with {len(vuln_ids)} vulnerability IDs...")
        policy_uuid = create_policy(
            namespace,
            project_uuid,
            vuln_ids,
            policy_name,
            tag,
            pr_id
        )
        print(f"PR policy created successfully (UUID: {policy_uuid}).")


def cleanup_pr_policy(namespace: str, project_uuid: str, pr_id: str) -> None:
    """
    Delete PR-specific exception policy (called when PR closes).
    
    Args:
        namespace: Endor namespace
        project_uuid: Endor project UUID
        pr_id: PR ID to clean up
    """
    tag = f"project-{project_uuid}-pr-{pr_id}"
    existing_policy = get_policy_by_tag(namespace, tag)
    
    if existing_policy:
        print(f"Deleting PR policy for PR {pr_id}...")
        delete_policy(namespace, existing_policy["uuid"])
        print(f"PR policy deleted successfully.")
    else:
        print(f"PR policy not found. Nothing to delete.")


def main():
    parser = argparse.ArgumentParser(
        description="Sync .endorignore file to Endor Labs exception policies"
    )
    parser.add_argument(
        "--namespace",
        required=True,
        help="Endor namespace (e.g., 'leonardo-learn')"
    )
    parser.add_argument(
        "--repo-url",
        required=True,
        help="Git repository URL (e.g., 'git@github.com:org/repo.git')"
    )
    parser.add_argument(
        "--pr-id",
        help="PR ID (if provided, syncs PR-specific policy; otherwise syncs main policy)"
    )
    parser.add_argument(
        "--ignore-file",
        default=".endorignore",
        help="Path to ignore file (default: .endorignore)"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Delete PR policy (use with --pr-id for PR cleanup)"
    )
    
    args = parser.parse_args()
    
    # Parse ignore file
    vuln_ids = parse_ignore_file(args.ignore_file)
    
    if not vuln_ids:
        print("No vulnerability IDs found in ignore file. Exiting.")
        return
    
    print(f"Found {len(vuln_ids)} vulnerability IDs in ignore file.")
    
    # Get project UUID
    print(f"Looking up project UUID for {args.repo_url}...")
    project_uuid = get_project_uuid(args.namespace, args.repo_url)
    
    if not project_uuid:
        print(f"ERROR: Project not found for {args.repo_url}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Project UUID: {project_uuid}")
    
    # Extract repo name from URL for policy naming
    # e.g., git@github.com:org/repo.git -> repo
    repo_name_match = re.search(r'[:/]([^/]+)\.git$', args.repo_url)
    repo_name = repo_name_match.group(1) if repo_name_match else "unknown"
    
    # Handle cleanup mode
    if args.cleanup:
        if not args.pr_id:
            print("ERROR: --pr-id is required for cleanup", file=sys.stderr)
            sys.exit(1)
        cleanup_pr_policy(args.namespace, project_uuid, args.pr_id)
        return
    
    # Sync policy
    if args.pr_id:
        sync_pr_policy(args.namespace, project_uuid, vuln_ids, repo_name, args.pr_id)
    else:
        sync_main_policy(args.namespace, project_uuid, vuln_ids, repo_name)


if __name__ == "__main__":
    main()

