import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
import json
import re

import diag_Final as Final

BASE_DIR = Path(__file__).resolve().parent
RUN_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
RUN_DIR = BASE_DIR / f"remedy_run_{RUN_TIMESTAMP}"
FIXED_TF_DIR = BASE_DIR / f"fixed_tf_{RUN_TIMESTAMP}"

SELECTED_RESULT = RUN_DIR / "selected_findings_snapshot.json"
FIXED_CHECKOV_RESULT = RUN_DIR / "step1_checkov_fixed.json"
FIXED_CUSTOM_RESULT = RUN_DIR / "step2_custom_fixed.json"
FIXED_MERGED_RESULT = RUN_DIR / "step3_merged_fixed.json"
SUMMARY_RESULT = RUN_DIR / "remediation_summary.json"


def build_finding_id(finding: Dict[str, Any]) -> str:
    check_id = str(finding.get("check_id", "")).strip()
    resource = str(finding.get("resource", "")).strip()
    return f"{check_id}::{resource}"


def load_selected_findings(filepath: Path) -> List[Dict[str, Any]]:
    data = Final.load_json(filepath)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("selected_findings", "merged_findings", "findings", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return value

    raise ValueError(
        "Selected findings JSON must contain a list or one of: "
        "selected_findings, merged_findings, findings, results"
    )


def load_selected_ids(filepath: Path) -> List[str]:
    data = Final.load_json(filepath)

    if isinstance(data, list):
        values = data
    elif isinstance(data, dict):
        values = data.get("selected_ids")
    else:
        values = None

    if not isinstance(values, list):
        raise ValueError("selected_ids JSON must contain a list or a selected_ids array")

    normalized = [str(item).strip() for item in values if str(item).strip()]
    if not normalized:
        raise ValueError("selected_ids JSON is empty")
    return normalized


def normalize_string_list(values: Any) -> List[str]:
    if not isinstance(values, list):
        return []
    return [str(item).strip() for item in values if str(item).strip()]


def load_selected_info(filepath: Path) -> tuple[List[str], List[Dict[str, Any]]]:
    data = Final.load_json(filepath)
    if not isinstance(data, dict):
        raise ValueError("selected_info JSON must be an object")

    selected_ids = normalize_string_list(
        data.get("selectedIds", data.get("selected_ids"))
    )

    raw_manual = data.get("selectedRemediations", data.get("selected_remediations"))
    if raw_manual is None:
        raw_manual = []
    if not isinstance(raw_manual, list):
        raise ValueError("selected_info JSON selectedRemediations must be an array")

    normalized_manual: List[Dict[str, Any]] = []
    manual_ids: List[str] = []

    for item in raw_manual:
        if not isinstance(item, dict):
            continue

        remediation_id = str(item.get("id", "")).strip()
        if not remediation_id:
            continue

        inputs = item.get("inputs")
        if not isinstance(inputs, dict):
            inputs = {}

        normalized_item = {
            "id": remediation_id,
            "inputs": inputs,
        }
        normalized_manual.append(normalized_item)
        manual_ids.append(remediation_id)

    merged_ids: List[str] = []
    for remediation_id in [*selected_ids, *manual_ids]:
        if remediation_id not in merged_ids:
            merged_ids.append(remediation_id)

    if not merged_ids:
        raise ValueError("selected_info JSON does not contain any selected remediation IDs")

    return merged_ids, normalized_manual


def merge_unique_ids(*id_lists: List[str]) -> List[str]:
    merged: List[str] = []
    for values in id_lists:
        for value in values:
            text = str(value).strip()
            if text and text not in merged:
                merged.append(text)
    return merged


def find_latest_diag_run_dir(base_dir: Path) -> Path | None:
    candidates = [
        path
        for path in base_dir.iterdir()
        if path.is_dir() and path.name.startswith("diag_run_")
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def resolve_latest_selected_path(base_dir: Path) -> Path | None:
    latest_run_dir = find_latest_diag_run_dir(base_dir)
    if latest_run_dir is None:
        return None

    summary_path = latest_run_dir / "diagnosis_summary.json"
    if summary_path.exists():
        try:
            summary = Final.load_json(summary_path)
            artifact_path = ((summary.get("artifacts") or {}).get("step3_merged")) or ""
            if artifact_path:
                candidate = Path(artifact_path)
                if candidate.exists():
                    return candidate
        except Exception:
            pass

    fallback = latest_run_dir / "step2_merged_source.json"
    if fallback.exists():
        return fallback

    return None


def resolve_latest_selection_inputs(base_dir: Path) -> tuple[Path | None, Path | None]:
    latest_run_dir = find_latest_diag_run_dir(base_dir)
    if latest_run_dir is None:
        return None, None

    selected_ids_path = latest_run_dir / "selected_ids.json"
    if not selected_ids_path.exists():
        selected_ids_path = None

    selected_info_path = latest_run_dir / "selected_info.json"
    if not selected_info_path.exists():
        selected_info_path = None

    return selected_ids_path, selected_info_path


def resolve_merged_result_from_selection_path(selection_path: Path, base_dir: Path) -> Path | None:
    candidate_paths = []

    parent = selection_path.parent
    candidate_paths.append(parent / "step2_merged_source.json")

    summary_path = parent / "diagnosis_summary.json"
    if summary_path.exists():
        try:
            summary = Final.load_json(summary_path)
            artifact_path = ((summary.get("artifacts") or {}).get("step3_merged")) or ""
            if artifact_path:
                candidate_paths.append(Path(artifact_path))
        except Exception:
            pass

    latest = resolve_latest_selected_path(base_dir)
    if latest is not None:
        candidate_paths.append(latest)

    for candidate in candidate_paths:
        if candidate and candidate.exists():
            return candidate.resolve()

    return None


def filter_findings_by_selected_ids(
    merged_result_path: Path,
    selected_ids: List[str],
) -> List[Dict[str, Any]]:
    merged_data = Final.load_json(merged_result_path)
    merged_findings = merged_data.get("merged_findings") or []
    selected_id_set = set(selected_ids)

    matched = [
        finding
        for finding in merged_findings
        if isinstance(finding, dict) and build_finding_id(finding) in selected_id_set
    ]
    return matched


def render_list_literal(values: List[str]) -> str:
    return "[" + ", ".join(json.dumps(str(value)) for value in values) + "]"


def render_ref_or_literal(value: str) -> str:
    text = str(value).strip()
    if not text:
        return '""'
    if text.startswith("aws_"):
        parsed = Final.parse_resource_identifier(text)
        if parsed:
            resource_type, resource_name = parsed
            return f"{resource_type}.{resource_name}.id"
    return json.dumps(text)


def merge_tags_attribute(block_text: str, new_tags: Dict[str, str]) -> str:
    tags_pattern = re.compile(r"(?ms)^([ \t]*)tags\s*=\s*\{\s*(.*?)^\1\}", re.MULTILINE)
    match = tags_pattern.search(block_text)

    if match:
        indent = match.group(1)
        body = match.group(2)
        entries: Dict[str, str] = {}
        order: List[str] = []

        for raw_line in body.splitlines():
            stripped = raw_line.strip()
            if not stripped or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            if key not in entries:
                order.append(key)
            entries[key] = value.strip()

        for key, value in new_tags.items():
            if key not in entries:
                order.append(key)
            entries[key] = json.dumps(value)

        rebuilt_lines = [f"{indent}tags = {{"]
        for key in order:
            rebuilt_lines.append(f"{indent}  {key} = {entries[key]}")
        rebuilt_lines.append(f"{indent}}}")
        rebuilt_block = "\n".join(rebuilt_lines)
        return block_text[:match.start()] + rebuilt_block + block_text[match.end():]

    tag_lines = ["  tags = {"]
    for key, value in new_tags.items():
        tag_lines.append(f"    {key} = {json.dumps(value)}")
    tag_lines.append("  }")
    return Final.insert_before_last_brace(block_text, "\n".join(tag_lines))


def apply_security_exception_tag(
    tf_dir: Path,
    resource_type: str,
    resource_name: str,
    check_id: str,
    decision_note: str = "",
) -> bool:
    normalized_check = check_id.replace(".", "_")
    tag_updates = {
        f"SecurityException{normalized_check}": "approved",
        "SecurityReviewStatus": "approved",
    }
    if decision_note:
        tag_updates["SecurityReviewNote"] = decision_note[:256]

    def _patch(block_text: str) -> str:
        return merge_tags_attribute(block_text, tag_updates)

    return Final.patch_resource_in_project(tf_dir, resource_type, resource_name, _patch)


def build_manual_remediation_lookup(
    selected_remediations: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    lookup: Dict[str, Dict[str, Any]] = {}
    for item in selected_remediations:
        remediation_id = str(item.get("id", "")).strip()
        if remediation_id:
            lookup[remediation_id] = item
    return lookup


def remediate_manual_ckv_aws_130(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    enabled = "true" if bool(inputs.get("mapPublicIpOnLaunch")) else "false"

    def _patch(block_text: str) -> str:
        return Final.replace_or_insert_attribute(block_text, "map_public_ip_on_launch", enabled)

    return Final.patch_resource_in_project(tf_dir, "aws_subnet", resource_name, _patch)


def remediate_manual_security_group(
    tf_dir: Path,
    finding: Dict[str, Any],
    inputs: Dict[str, Any],
) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    direction = str(inputs.get("direction", "ingress")).strip() or "ingress"
    cidr = str(inputs.get("cidr", "")).strip()
    protocol = str(inputs.get("protocol", "tcp")).strip() or "tcp"
    from_port = inputs.get("fromPort")
    to_port = inputs.get("toPort")
    source_type = str(inputs.get("allowedSourceType", "cidr")).strip() or "cidr"
    source_sg = str(inputs.get("allowedSourceSecurityGroupId", "")).strip()

    attributes: Dict[str, str] = {
        "protocol": json.dumps(protocol),
    }
    if from_port is not None:
        attributes["from_port"] = str(from_port)
    if to_port is not None:
        attributes["to_port"] = str(to_port)

    if source_type == "security_group" and source_sg:
        attributes["security_groups"] = f"[{render_ref_or_literal(source_sg)}]"
        attributes["cidr_blocks"] = "[]"
        attributes["ipv6_cidr_blocks"] = "[]"
    elif cidr:
        attributes["cidr_blocks"] = render_list_literal([cidr])
        attributes["security_groups"] = "[]"

    def _patch(block_text: str) -> str:
        updated, changed = Final.patch_child_block_attributes(block_text, direction, attributes)
        if changed:
            return updated

        child_lines = [f"  {direction} {{"]
        for key, value in attributes.items():
            child_lines.append(f"    {key} = {value}")
        child_lines.append("  }")
        return Final.insert_before_last_brace(block_text, "\n".join(child_lines))

    return Final.patch_resource_in_project(tf_dir, "aws_security_group", resource_name, _patch)


def remediate_manual_ckv2_aws_41(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    profile_arn = str(inputs.get("instanceProfileArn", "")).strip()
    if not profile_arn:
        return False

    def _patch(block_text: str) -> str:
        return Final.replace_or_insert_attribute(block_text, "iam_instance_profile", json.dumps(profile_arn))

    return Final.patch_resource_in_project(tf_dir, "aws_instance", resource_name, _patch)


def remediate_manual_ckv2_aws_64(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    policy_document = str(inputs.get("policyDocument", "")).strip()
    if not policy_document:
        return False
    policy_expr = '<<POLICY\n' + policy_document + '\nPOLICY'

    def _patch(block_text: str) -> str:
        return Final.replace_or_insert_attribute(block_text, "policy", policy_expr)

    return Final.patch_resource_in_project(tf_dir, "aws_kms_key", resource_name, _patch)


def remediate_manual_waf_rules(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    managed_rule_group = str(inputs.get("managedRuleGroup", "")).strip()
    if not managed_rule_group:
        return False

    def _patch(block_text: str) -> str:
        if managed_rule_group in block_text:
            return block_text
        rule_name = managed_rule_group.lower().replace("_", "-")
        insertion = f'''  rule {{
    name     = "{rule_name}"
    priority = 100

    override_action {{
      none {{}}
    }}

    statement {{
      managed_rule_group_statement {{
        name        = "{managed_rule_group}"
        vendor_name = "AWS"
      }}
    }}

    visibility_config {{
      cloudwatch_metrics_enabled = true
      metric_name                = "{rule_name}"
      sampled_requests_enabled   = true
    }}
  }}'''
        return Final.insert_before_last_brace(block_text, insertion)

    changed = Final.patch_resource_in_project(tf_dir, "aws_wafv2_web_acl", resource_name, _patch)

    associate_to = str(inputs.get("associateToResourceArn", "")).strip()
    if associate_to:
        assoc_name = f"{resource_name}_association"
        assoc_block = f'''resource "aws_wafv2_web_acl_association" "{assoc_name}" {{
  resource_arn = {json.dumps(associate_to)}
  web_acl_arn  = aws_wafv2_web_acl.{resource_name}.arn
}}'''
        if Final.append_resource_if_missing(
            tf_dir,
            "waf_manual_remediation.tf",
            "aws_wafv2_web_acl_association",
            assoc_name,
            assoc_block,
        ):
            changed = True

    return changed


def remediate_manual_ckv2_aws_31(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    log_destination = str(inputs.get("logDestinationArn", "")).strip()
    redacted_fields = inputs.get("redactedFields") or []
    if not log_destination:
        return False

    redacted_blocks = ""
    for field in redacted_fields:
        field_text = str(field).strip()
        if not field_text:
            continue
        if "." in field_text:
            field_type, field_value = field_text.split(".", 1)
            redacted_blocks += f'''
  redacted_fields {{
    {field_type} {{
      name = "{field_value}"
    }}
  }}'''

    block = f'''resource "aws_wafv2_web_acl_logging_configuration" "{resource_name}" {{
  resource_arn            = aws_wafv2_web_acl.{resource_name}.arn
  log_destination_configs = [{json.dumps(log_destination)}]{redacted_blocks}
}}'''
    return Final.append_resource_if_missing(
        tf_dir,
        "waf_manual_remediation.tf",
        "aws_wafv2_web_acl_logging_configuration",
        resource_name,
        block,
    )


def remediate_manual_ckv2_aws_62(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    target_type = str(inputs.get("targetType", "")).strip().lower()
    target_arn = str(inputs.get("targetArn", "")).strip()
    events = [str(item).strip() for item in (inputs.get("events") or []) if str(item).strip()]
    if not target_type or not target_arn or not events:
        return False

    filter_prefix = str(inputs.get("filterPrefix", "")).strip()
    filter_suffix = str(inputs.get("filterSuffix", "")).strip()
    event_lines = render_list_literal(events)
    target_block_name = {
        "sqs": "queue",
        "lambda": "lambda_function",
        "sns": "topic",
    }.get(target_type, "queue")
    target_arg_name = {
        "sqs": "queue_arn",
        "lambda": "lambda_function_arn",
        "sns": "topic_arn",
    }.get(target_type, "queue_arn")

    filter_lines = ""
    if filter_prefix:
        filter_lines += f'\n    filter_prefix = {json.dumps(filter_prefix)}'
    if filter_suffix:
        filter_lines += f'\n    filter_suffix = {json.dumps(filter_suffix)}'

    block = f'''resource "aws_s3_bucket_notification" "{resource_name}" {{
  bucket = aws_s3_bucket.{resource_name}.id

  {target_block_name} {{
    {target_arg_name} = {json.dumps(target_arn)}
    events            = {event_lines}{filter_lines}
  }}
}}'''
    return Final.append_resource_if_missing(
        tf_dir,
        "s3_manual_remediation.tf",
        "aws_s3_bucket_notification",
        resource_name,
        block,
    )


def remediate_manual_ckv_aws_18(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    target_bucket = str(inputs.get("targetBucket", "")).strip()
    target_prefix = str(inputs.get("targetPrefix", "")).strip()
    if not target_bucket:
        return False

    block = f'''resource "aws_s3_bucket_logging" "{resource_name}" {{
  bucket        = aws_s3_bucket.{resource_name}.id
  target_bucket = {render_ref_or_literal(target_bucket)}
  target_prefix = {json.dumps(target_prefix)}
}}'''
    return Final.append_resource_if_missing(
        tf_dir,
        "s3_manual_remediation.tf",
        "aws_s3_bucket_logging",
        resource_name,
        block,
    )


def remediate_manual_ckv_aws_144(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    destination_bucket_arn = str(inputs.get("destinationBucketArn", "")).strip()
    replication_role_arn = str(inputs.get("replicationRoleArn", "")).strip()
    replica_kms_key_arn = str(inputs.get("replicaKmsKeyArn", "")).strip()
    replicate_delete_markers = bool(inputs.get("replicateDeleteMarkers"))
    if not destination_bucket_arn or not replication_role_arn:
        return False

    kms_lines = ""
    if replica_kms_key_arn:
        kms_lines = f'''
        encryption_configuration {{
          replica_kms_key_id = {json.dumps(replica_kms_key_arn)}
        }}'''

    block = f'''resource "aws_s3_bucket_replication_configuration" "{resource_name}" {{
  bucket = aws_s3_bucket.{resource_name}.id
  role   = {json.dumps(replication_role_arn)}

  rule {{
    id     = "cross-region-replication"
    status = "Enabled"

    delete_marker_replication {{
      status = {"Enabled" if replicate_delete_markers else "Disabled"}
    }}

    destination {{
      bucket        = {json.dumps(destination_bucket_arn)}
      storage_class = "STANDARD"{kms_lines}
    }}
  }}
}}'''
    return Final.append_resource_if_missing(
        tf_dir,
        "s3_manual_remediation.tf",
        "aws_s3_bucket_replication_configuration",
        resource_name,
        block,
    )


def remediate_manual_ckv2_aws_57(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    lambda_arn = str(inputs.get("rotationLambdaArn", "")).strip()
    interval_days = inputs.get("rotationIntervalDays")
    if not lambda_arn or interval_days in (None, ""):
        return False

    block = f'''resource "aws_secretsmanager_secret_rotation" "{resource_name}" {{
  secret_id           = aws_secretsmanager_secret.{resource_name}.id
  rotation_lambda_arn = {json.dumps(lambda_arn)}

  rotation_rules {{
    automatically_after_days = {interval_days}
  }}
}}'''
    return Final.append_resource_if_missing(
        tf_dir,
        "secrets_manager_manual_remediation.tf",
        "aws_secretsmanager_secret_rotation",
        resource_name,
        block,
    )


def remediate_manual_3_4(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False
    _, resource_name = parsed
    cidr = str(inputs.get("cidr", "0.0.0.0/0")).strip() or "0.0.0.0/0"
    target_type = str(inputs.get("targetType", "")).strip()
    target_resource_id = str(inputs.get("targetResourceId", "")).strip()
    if not target_type or not target_resource_id:
        return False

    target_attr_map = {
        "nat_gateway": "nat_gateway_id",
        "internet_gateway": "gateway_id",
    }
    target_attr = target_attr_map.get(target_type)
    if not target_attr:
        return False

    target_expr = render_ref_or_literal(target_resource_id)
    attributes = {
        "cidr_block": json.dumps(cidr),
        target_attr: target_expr,
    }

    def _patch(block_text: str) -> str:
        updated, changed = Final.patch_child_block_attributes(block_text, "route", attributes)
        if changed:
            return updated

        child_lines = [f"  route {{"]
        for key, value in attributes.items():
            child_lines.append(f"    {key} = {value}")
        child_lines.append("  }")
        return Final.insert_before_last_brace(block_text, "\n".join(child_lines))

    route_changed = Final.patch_resource_in_project(tf_dir, "aws_route_table", resource_name, _patch)
    tag_changed = apply_security_exception_tag(
        tf_dir,
        "aws_route_table",
        resource_name,
        "3.4",
        str(inputs.get("decisionNote", "")).strip(),
    )
    return route_changed or tag_changed


def remediate_manual_decision_only(tf_dir: Path, finding: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
    parsed = Final.parse_resource_identifier(str(finding.get("resource", "")).strip())
    if not parsed:
        return False

    resource_type, resource_name = parsed
    check_id = str(finding.get("check_id", "")).strip()
    decision = str(inputs.get("decision", "keep")).strip().lower() or "keep"
    decision_note = str(inputs.get("decisionNote", "")).strip()

    if decision != "keep":
        return False

    return apply_security_exception_tag(
        tf_dir,
        resource_type,
        resource_name,
        check_id,
        decision_note,
    )


MANUAL_REMEDIATION_RULES = {
    "CKV_AWS_130": remediate_manual_ckv_aws_130,
    "CKV_AWS_382": remediate_manual_security_group,
    "CKV_AWS_260": remediate_manual_security_group,
    "3.1": remediate_manual_security_group,
    "CKV2_AWS_41": remediate_manual_ckv2_aws_41,
    "CKV2_AWS_64": remediate_manual_ckv2_aws_64,
    "CKV_AWS_192": remediate_manual_waf_rules,
    "CKV2_AWS_76": remediate_manual_waf_rules,
    "CKV2_AWS_31": remediate_manual_ckv2_aws_31,
    "CKV2_AWS_62": remediate_manual_ckv2_aws_62,
    "CKV_AWS_18": remediate_manual_ckv_aws_18,
    "CKV_AWS_144": remediate_manual_ckv_aws_144,
    "CKV2_AWS_57": remediate_manual_ckv2_aws_57,
    "3.4": remediate_manual_3_4,
    "3.5": remediate_manual_decision_only,
    "3.6": remediate_manual_decision_only,
}


def apply_manual_remediations(
    tf_dir: Path,
    selected_findings: List[Dict[str, Any]],
    selected_remediations: List[Dict[str, Any]],
) -> tuple[int, int]:
    manual_lookup = build_manual_remediation_lookup(selected_remediations)
    patched_count = 0
    skipped_count = 0

    for finding in selected_findings:
        finding_id = build_finding_id(finding)
        manual_selection = manual_lookup.get(finding_id)
        if not manual_selection:
            continue

        check_id = str(finding.get("check_id", "")).strip()
        remediation_fn = MANUAL_REMEDIATION_RULES.get(check_id)
        if remediation_fn is None:
            print(f"[SKIP] No manual remediation rule: {check_id} / {finding_id}")
            skipped_count += 1
            continue

        try:
            changed = remediation_fn(tf_dir, finding, manual_selection.get("inputs", {}))
            if changed:
                patched_count += 1
            else:
                skipped_count += 1
                print(f"[SKIP] Manual remediation not applied: {check_id} / {finding_id}")
        except Exception as exc:
            skipped_count += 1
            print(f"[ERROR] Manual remediation error: {check_id} / {finding_id} / {exc}")

    if patched_count:
        Final.run_terraform_fmt(tf_dir)

    return patched_count, skipped_count


def main() -> None:
    if len(sys.argv) >= 2:
        selected_path = Path(sys.argv[1]).resolve()
        if not selected_path.exists():
            print(f"[ERROR] selected findings file not found: {selected_path}")
            return
        selected_mode = "manual"
        selected_ids_path_for_summary: Path | None = None
        selected_info_path_for_summary: Path | None = None
    else:
        auto_selected, auto_selected_info = resolve_latest_selection_inputs(BASE_DIR)
        if auto_selected is None and auto_selected_info is None:
            print("Usage: python remedy_Final.py <selected_ids.json | selected_info.json | selected_findings.json>")
            print("[ERROR] Could not find latest selected_ids.json or selected_info.json automatically.")
            return
        selected_path = (auto_selected_info or auto_selected).resolve()
        selected_ids_path_for_summary = auto_selected.resolve() if auto_selected else None
        selected_info_path_for_summary = auto_selected_info.resolve() if auto_selected_info else None
        if auto_selected and auto_selected_info:
            selected_mode = "auto-latest-selected-ids-and-info"
            print(f"[AUTO] Using latest selected IDs: {auto_selected.resolve()}")
            print(f"[AUTO] Using latest selected info: {auto_selected_info.resolve()}")
        elif auto_selected_info:
            selected_mode = "auto-latest-selected-info"
            print(f"[AUTO] Using latest selected info: {auto_selected_info.resolve()}")
        else:
            selected_mode = "auto-latest-selected-ids"
            print(f"[AUTO] Using latest selected IDs: {auto_selected.resolve()}")

    if not Final.SOURCE_TF_DIR.exists():
        print(f"[ERROR] source_tf not found: {Final.SOURCE_TF_DIR}")
        return

    RUN_DIR.mkdir(parents=True, exist_ok=True)

    selected_findings: List[Dict[str, Any]]
    merged_result_path: Path | None = None
    selected_ids: List[str] = []
    selected_remediations: List[Dict[str, Any]] = []
    auto_findings: List[Dict[str, Any]] = []
    manual_findings: List[Dict[str, Any]] = []

    if len(sys.argv) < 2 and selected_mode == "auto-latest-selected-ids-and-info":
        if selected_ids_path_for_summary is None or selected_info_path_for_summary is None:
            print("[ERROR] Latest selection inputs were not resolved correctly.")
            return

        selected_ids_from_file = load_selected_ids(selected_ids_path_for_summary)
        selected_ids_from_info, selected_remediations = load_selected_info(selected_info_path_for_summary)
        selected_ids = merge_unique_ids(selected_ids_from_file, selected_ids_from_info)
        merged_result_path = resolve_merged_result_from_selection_path(selected_info_path_for_summary, BASE_DIR)
        if merged_result_path is None:
            print(f"[ERROR] Could not resolve step2_merged_source.json for {selected_info_path_for_summary}")
            return

        selected_findings = filter_findings_by_selected_ids(merged_result_path, selected_ids)
        if not selected_findings:
            print(
                "[ERROR] No findings matched combined selected_ids.json and selected_info.json "
                f"from {selected_ids_path_for_summary.parent}"
            )
            return

        print(
            f"[INFO] Matched {len(selected_findings)} findings "
            f"({len(selected_ids_from_file)} auto IDs, {len(selected_remediations)} manual selections) "
            f"from {merged_result_path}"
        )
    elif selected_path.name == "selected_ids.json":
        selected_ids = load_selected_ids(selected_path)
        merged_result_path = resolve_merged_result_from_selection_path(selected_path, BASE_DIR)
        if merged_result_path is None:
            print(f"[ERROR] Could not resolve step2_merged_source.json for {selected_path}")
            return

        selected_findings = filter_findings_by_selected_ids(merged_result_path, selected_ids)
        if not selected_findings:
            print(f"[ERROR] No findings matched selected IDs from {selected_path}")
            return

        print(f"[INFO] Matched {len(selected_findings)} findings from {merged_result_path}")
    elif selected_path.name == "selected_info.json":
        selected_ids, selected_remediations = load_selected_info(selected_path)
        merged_result_path = resolve_merged_result_from_selection_path(selected_path, BASE_DIR)
        if merged_result_path is None:
            print(f"[ERROR] Could not resolve step2_merged_source.json for {selected_path}")
            return

        selected_findings = filter_findings_by_selected_ids(merged_result_path, selected_ids)
        if not selected_findings:
            print(f"[ERROR] No findings matched selected_info IDs from {selected_path}")
            return

        print(
            f"[INFO] Matched {len(selected_findings)} findings "
            f"({len(selected_remediations)} manual selections) from {merged_result_path}"
        )
    else:
        selected_findings = load_selected_findings(selected_path)

    Final.write_json(
        SELECTED_RESULT,
        {
            "selected_findings": selected_findings,
            "selected_ids": selected_ids,
            "selected_remediations": selected_remediations,
        },
    )

    print("=== STEP 1: Remediation on selected findings ===")
    manual_id_set = {
        str(item.get("id", "")).strip()
        for item in selected_remediations
        if str(item.get("id", "")).strip()
    }
    if manual_id_set:
        auto_findings = [
            finding
            for finding in selected_findings
            if build_finding_id(finding) not in manual_id_set
        ]
        manual_findings = [
            finding
            for finding in selected_findings
            if build_finding_id(finding) in manual_id_set
        ]
    else:
        auto_findings = list(selected_findings)

    auto_patched_count, auto_skipped_count = Final.remediate_findings(
        auto_findings,
        Final.SOURCE_TF_DIR,
        FIXED_TF_DIR,
    )
    print(f"[AUTO REMEDIATION] patched={auto_patched_count}, skipped={auto_skipped_count}")

    manual_patched_count, manual_skipped_count = apply_manual_remediations(
        FIXED_TF_DIR,
        manual_findings,
        selected_remediations,
    )
    if manual_findings:
        print(f"[MANUAL REMEDIATION] patched={manual_patched_count}, skipped={manual_skipped_count}")

    patched_count = auto_patched_count + manual_patched_count
    skipped_count = auto_skipped_count + manual_skipped_count

    print("\n=== STEP 2: Re-diagnosis on fixed directory ===")
    fixed_plan = FIXED_TF_DIR / "tfplan.json"
    Final.run_terraform_plan(FIXED_TF_DIR, fixed_plan)
    checkov_after = Final.run_checkov(FIXED_TF_DIR, FIXED_CHECKOV_RESULT)
    custom_after = Final.run_custom_diagnosis(fixed_plan, FIXED_CUSTOM_RESULT)

    print("\n=== STEP 3: Merge re-diagnosis results ===")
    merged_after = Final.merge_findings(checkov_after, custom_after, FIXED_MERGED_RESULT)

    summary = {
        "run_timestamp": RUN_TIMESTAMP,
        "run_type": "remediation_and_rediagnosis",
        "selected_findings_path": str(selected_path),
        "selected_findings_mode": selected_mode,
        "selected_ids_path": str(selected_ids_path_for_summary) if selected_ids_path_for_summary else None,
        "selected_info_path": str(selected_info_path_for_summary) if selected_info_path_for_summary else None,
        "resolved_merged_result_path": str(merged_result_path) if merged_result_path else None,
        "source_tf_dir": str(Final.SOURCE_TF_DIR),
        "fixed_tf_dir": str(FIXED_TF_DIR),
        "selected_findings_count": len(selected_findings),
        "selected_auto_findings_count": len(auto_findings),
        "selected_manual_findings_count": len(manual_findings),
        "selected_ids_count": len(selected_ids),
        "selected_manual_remediations_count": len(selected_remediations),
        "auto_patched_count": auto_patched_count,
        "auto_skipped_count": auto_skipped_count,
        "manual_patched_count": manual_patched_count,
        "manual_skipped_count": manual_skipped_count,
        "patched_count": patched_count,
        "skipped_count": skipped_count,
        "recheck_checkov_failed": len(Final.deduplicate_failed_checks(checkov_after)),
        "recheck_custom_findings": len(custom_after),
        "recheck_merged_findings": len(merged_after),
        "artifacts": {
            "selected_snapshot": str(SELECTED_RESULT),
            "step1_checkov_fixed": str(FIXED_CHECKOV_RESULT),
            "step2_custom_fixed": str(FIXED_CUSTOM_RESULT),
            "step3_merged_fixed": str(FIXED_MERGED_RESULT),
        },
    }
    Final.write_json(SUMMARY_RESULT, summary)

    print("\n=== Remediation complete ===")
    print(f"fixed_tf = {FIXED_TF_DIR}")
    print(f"run_dir  = {RUN_DIR}")
    print(f"summary  = {SUMMARY_RESULT}")


if __name__ == "__main__":
    main()

