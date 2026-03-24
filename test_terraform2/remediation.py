import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_TF_DIR = os.path.join(BASE_DIR, "source_tf")
FIXED_TF_DIR = os.path.join(BASE_DIR, "fixed_tf")
RESULT_JSON = os.path.join(BASE_DIR, "result.json")


def load_json(filepath: str) -> Dict[str, Any]:
    with open(filepath, "r", encoding="utf-8") as file:
        return json.load(file)


def ensure_clean_directory(target_dir: str) -> None:
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    os.makedirs(target_dir, exist_ok=True)


def copy_tf_project(src_dir: str, dst_dir: str) -> None:
    ensure_clean_directory(dst_dir)

    for item in os.listdir(src_dir):
        src_path = os.path.join(src_dir, item)
        dst_path = os.path.join(dst_dir, item)

        if os.path.isdir(src_path):
            shutil.copytree(src_path, dst_path)
        else:
            shutil.copy2(src_path, dst_path)


def list_tf_files(tf_dir: str) -> List[str]:
    tf_files = []
    for root, _, files in os.walk(tf_dir):
        for file in files:
            if file.endswith(".tf"):
                tf_files.append(os.path.join(root, file))
    return tf_files


def read_text(filepath: str) -> str:
    with open(filepath, "r", encoding="utf-8") as file:
        return file.read()


def write_text(filepath: str, content: str) -> None:
    with open(filepath, "w", encoding="utf-8") as file:
        file.write(content)


def run_terraform_fmt(tf_dir: str) -> None:
    try:
        subprocess.run(
            ["terraform", "fmt", "-recursive"],
            cwd=tf_dir,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("terraform command not found. Skipping terraform fmt.")


def find_resource_block(text: str, resource_type: str, resource_name: str) -> Optional[Tuple[int, int]]:
    pattern = re.compile(
        rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{',
        re.MULTILINE,
    )
    match = pattern.search(text)
    if not match:
        return None

    start = match.start()
    brace_start = match.end() - 1
    depth = 0

    for index in range(brace_start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return start, index + 1

    return None


def find_block_ranges(text: str, block_name: str) -> List[Tuple[int, int]]:
    pattern = re.compile(rf'(?m)^([ \t]*){re.escape(block_name)}\s*\{{')
    ranges: List[Tuple[int, int]] = []

    for match in pattern.finditer(text):
        brace_start = match.end() - 1
        depth = 0

        for index in range(brace_start, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    ranges.append((match.start(), index + 1))
                    break

    return ranges


def insert_before_last_brace(block_text: str, insertion: str) -> str:
    last_brace = block_text.rfind("}")
    if last_brace == -1:
        return block_text
    return block_text[:last_brace].rstrip() + "\n\n" + insertion.rstrip() + "\n" + block_text[last_brace:]


def replace_or_insert_attribute(block_text: str, key: str, value_expr: str, indent: str = "  ") -> str:
    attr_pattern = re.compile(rf"(?m)^([ \t]*){re.escape(key)}\s*=\s*.*$")
    replacement = f"{indent}{key} = {value_expr}"

    if attr_pattern.search(block_text):
        return attr_pattern.sub(replacement, block_text, count=1)

    return insert_before_last_brace(block_text, replacement)


def patch_child_block_attributes(block_text: str, child_block_name: str, attributes: Dict[str, str]) -> Tuple[str, bool]:
    ranges = find_block_ranges(block_text, child_block_name)
    if not ranges:
        return block_text, False

    changed = False
    updated_text = block_text

    for start, end in reversed(ranges):
        child_block = updated_text[start:end]
        new_child_block = child_block

        indent_match = re.search(r"(?m)^([ \t]*)" + re.escape(child_block_name) + r"\s*\{", child_block)
        base_indent = indent_match.group(1) if indent_match else ""
        attr_indent = base_indent + "  "

        for key, value_expr in attributes.items():
            newer_child_block = replace_or_insert_attribute(new_child_block, key, value_expr, indent=attr_indent)
            if newer_child_block != new_child_block:
                changed = True
                new_child_block = newer_child_block

        updated_text = updated_text[:start] + new_child_block + updated_text[end:]

    return updated_text, changed


def resource_exists_in_text(text: str, resource_type: str, resource_name: str) -> bool:
    return find_resource_block(text, resource_type, resource_name) is not None


def patch_resource_in_file(filepath: str, resource_type: str, resource_name: str, patch_fn) -> bool:
    text = read_text(filepath)
    block_range = find_resource_block(text, resource_type, resource_name)
    if not block_range:
        return False

    start, end = block_range
    old_block = text[start:end]
    new_block = patch_fn(old_block)

    if new_block == old_block:
        return False

    new_text = text[:start] + new_block + text[end:]
    write_text(filepath, new_text)
    return True


def patch_resource_in_project(tf_dir: str, resource_type: str, resource_name: str, patch_fn) -> bool:
    for tf_file in list_tf_files(tf_dir):
        if patch_resource_in_file(tf_file, resource_type, resource_name, patch_fn):
            print(f"[PATCHED] {resource_type}.{resource_name} in {os.path.basename(tf_file)}")
            return True
    return False


def append_resource_to_file(filepath: str, resource_block: str) -> None:
    text = read_text(filepath)
    new_text = text.rstrip() + "\n\n" + resource_block.rstrip() + "\n"
    write_text(filepath, new_text)


def append_resource_to_project(tf_dir: str, filename: str, resource_block: str) -> None:
    target_file = os.path.join(tf_dir, filename)
    if not os.path.exists(target_file):
        write_text(target_file, "")
    append_resource_to_file(target_file, resource_block)


def build_resource_identifier(result: Dict[str, Any]) -> str:
    resource = str(result.get("resource", "")).strip()
    if resource:
        return resource

    resource_type = str(result.get("resource_type", "")).strip()
    resource_name = str(result.get("resource_name", "")).strip()
    if resource_type and resource_name:
        return f"{resource_type}.{resource_name}"

    return ""


def parse_resource_identifier(result: Dict[str, Any], expected_type: Optional[str] = None) -> Optional[str]:
    resource = build_resource_identifier(result)
    match = re.match(r"^([A-Za-z0-9_]+)\.([A-Za-z0-9_\-]+)$", resource)
    if not match:
        return None

    resource_type, resource_name = match.groups()
    if expected_type and resource_type != expected_type:
        return None

    return resource_name


def find_first_matching_resource_name(tf_dir: str, resource_type: str, bucket_name: str) -> Optional[str]:
    candidates = [
        bucket_name,
        f"{bucket_name}_access",
        f"{bucket_name}_acl",
        f"{bucket_name}_policy",
        f"{bucket_name}_public_access_block",
        f"{bucket_name}_pab",
    ]

    for tf_file in list_tf_files(tf_dir):
        text = read_text(tf_file)
        for candidate in candidates:
            if resource_exists_in_text(text, resource_type, candidate):
                return candidate

        pattern = re.compile(
            rf'resource\s+"{re.escape(resource_type)}"\s+"([^"]+)"\s*\{{(?:(?!resource\s+").)*?bucket\s*=\s*aws_s3_bucket\.{re.escape(bucket_name)}\.(?:id|bucket)',
            re.DOTALL,
        )
        match = pattern.search(text)
        if match:
            return match.group(1)

    return None


def remediate_3_7_s3_access(tf_dir: str, result: Dict[str, Any]) -> bool:
    bucket_name = parse_resource_identifier(result, "aws_s3_bucket")
    if not bucket_name:
        return False

    changed = False

    pab_resource_name = find_first_matching_resource_name(
        tf_dir, "aws_s3_bucket_public_access_block", bucket_name
    ) or bucket_name

    def _patch_public_access_block(block_text: str) -> str:
        updated = block_text
        updated = replace_or_insert_attribute(updated, "bucket", f"aws_s3_bucket.{bucket_name}.id")
        updated = replace_or_insert_attribute(updated, "block_public_acls", "true")
        updated = replace_or_insert_attribute(updated, "ignore_public_acls", "true")
        updated = replace_or_insert_attribute(updated, "block_public_policy", "true")
        updated = replace_or_insert_attribute(updated, "restrict_public_buckets", "true")
        return updated

    if patch_resource_in_project(
        tf_dir, "aws_s3_bucket_public_access_block", pab_resource_name, _patch_public_access_block
    ):
        changed = True
    else:
        new_block = f'''resource "aws_s3_bucket_public_access_block" "{pab_resource_name}" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}}'''
        append_resource_to_project(tf_dir, "s3_access_remediation.tf", new_block)
        print(f"[ADDED] Public access block for aws_s3_bucket.{bucket_name}")
        changed = True

    acl_resource_name = find_first_matching_resource_name(
        tf_dir, "aws_s3_bucket_acl", bucket_name
    ) or bucket_name

    def _patch_acl(block_text: str) -> str:
        updated = block_text
        updated = replace_or_insert_attribute(updated, "bucket", f"aws_s3_bucket.{bucket_name}.id")
        updated = replace_or_insert_attribute(updated, "acl", '"private"')
        return updated

    if patch_resource_in_project(tf_dir, "aws_s3_bucket_acl", acl_resource_name, _patch_acl):
        changed = True
    else:
        acl_block = f'''resource "aws_s3_bucket_acl" "{acl_resource_name}" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  acl    = "private"
}}'''
        append_resource_to_project(tf_dir, "s3_access_remediation.tf", acl_block)
        print(f"[ADDED] Private ACL for aws_s3_bucket.{bucket_name}")
        changed = True

    policy_resource_name = find_first_matching_resource_name(
        tf_dir, "aws_s3_bucket_policy", bucket_name
    )
    if policy_resource_name:
        print(
            f"[INFO] aws_s3_bucket_policy.{policy_resource_name} exists for aws_s3_bucket.{bucket_name}. "
            "Public bucket policy cleanup is not auto-rewritten."
        )

    return changed


def remediate_3_9_alb(tf_dir: str, result: Dict[str, Any]) -> bool:
    resource_name = parse_resource_identifier(result, "aws_lb")
    if not resource_name:
        return False

    def _patch(block_text: str) -> str:
        updated = block_text
        updated = replace_or_insert_attribute(updated, "drop_invalid_header_fields", "true")
        updated = replace_or_insert_attribute(updated, "enable_deletion_protection", "true")
        return updated

    return patch_resource_in_project(tf_dir, "aws_lb", resource_name, _patch)


def remediate_4_1_ebs(tf_dir: str, result: Dict[str, Any]) -> bool:
    resource_name = parse_resource_identifier(result, "aws_instance")
    if not resource_name:
        return False

    def _patch(block_text: str) -> str:
        updated, changed = patch_child_block_attributes(
            block_text,
            "root_block_device",
            {
                "encrypted": "true",
            },
        )
        if changed:
            return updated

        insertion = """  root_block_device {
    encrypted             = true
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }"""
        return insert_before_last_brace(block_text, insertion)

    return patch_resource_in_project(tf_dir, "aws_instance", resource_name, _patch)


def remediate_4_2_rds(tf_dir: str, result: Dict[str, Any]) -> bool:
    resource_name = parse_resource_identifier(result, "aws_db_instance")
    if not resource_name:
        return False

    def _patch(block_text: str) -> str:
        updated = replace_or_insert_attribute(block_text, "storage_encrypted", "true")
        if "kms_key_id" not in updated:
            return updated
        return updated

    return patch_resource_in_project(tf_dir, "aws_db_instance", resource_name, _patch)


def remediate_4_3_s3(tf_dir: str, result: Dict[str, Any]) -> bool:
    bucket_name = parse_resource_identifier(result, "aws_s3_bucket")
    if not bucket_name:
        return False

    sse_resource_name = find_first_matching_resource_name(
        tf_dir, "aws_s3_bucket_server_side_encryption_configuration", bucket_name
    ) or bucket_name

    def _patch_sse(block_text: str) -> str:
        if 'sse_algorithm = "AES256"' in block_text or 'sse_algorithm = "aws:kms"' in block_text:
            return block_text

        updated = block_text
        updated = replace_or_insert_attribute(updated, "bucket", f"aws_s3_bucket.{bucket_name}.id")
        if "rule {" not in updated:
            rule_block = """  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }"""
            updated = insert_before_last_brace(updated, rule_block)
        return updated

    if patch_resource_in_project(
        tf_dir,
        "aws_s3_bucket_server_side_encryption_configuration",
        sse_resource_name,
        _patch_sse,
    ):
        return True

    new_block = f'''resource "aws_s3_bucket_server_side_encryption_configuration" "{sse_resource_name}" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}'''

    append_resource_to_project(tf_dir, "s3_remediation.tf", new_block)
    print(f"[ADDED] S3 SSE config for aws_s3_bucket.{bucket_name}")
    return True


REMEDIATION_RULES = {
    "3.7": remediate_3_7_s3_access,
    "3.9": remediate_3_9_alb,
    "4.1": remediate_4_1_ebs,
    "4.2": remediate_4_2_rds,
    "4.3": remediate_4_3_s3,
}


def get_vulnerable_results(result_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = result_data.get("results", [])
    return [
        finding
        for finding in findings
        if str(finding.get("status", "")).lower() in ["vulnerable", "fail"]
    ]


def main() -> None:
    if not os.path.exists(SOURCE_TF_DIR):
        print(f"Source Terraform directory does not exist: {SOURCE_TF_DIR}")
        return

    if not os.path.exists(RESULT_JSON):
        print(f"Diagnosis result file does not exist: {RESULT_JSON}")
        return

    result_data = load_json(RESULT_JSON)
    vulnerable_results = get_vulnerable_results(result_data)

    if not vulnerable_results:
        print("No vulnerable findings found. Skipping remediation.")
        return

    copy_tf_project(SOURCE_TF_DIR, FIXED_TF_DIR)
    print(f"[COPIED] {SOURCE_TF_DIR} -> {FIXED_TF_DIR}")

    patched_count = 0
    skipped_count = 0

    for result in vulnerable_results:
        check_code = str(result.get("code") or result.get("check_code") or "")
        remediation_fn = REMEDIATION_RULES.get(check_code)
        resource = build_resource_identifier(result)

        if not remediation_fn:
            print(f"[SKIP] No remediation function: check_code={check_code}")
            skipped_count += 1
            continue

        changed = remediation_fn(FIXED_TF_DIR, result)
        if changed:
            patched_count += 1
        else:
            skipped_count += 1
            print(f"[SKIP] No change applied: check_code={check_code}, resource={resource}")

    run_terraform_fmt(FIXED_TF_DIR)

    print("\n=== Remediation Complete ===")
    print(f"patched_count = {patched_count}")
    print(f"skipped_count = {skipped_count}")
    print(f"fixed_tf_dir  = {FIXED_TF_DIR}")


if __name__ == "__main__":
    main()
