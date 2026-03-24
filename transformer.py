import argparse
import json
import re
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent

INDEX_PATH_RE = re.compile(r"/\[\d+\]")
INLINE_INDEX_RE = re.compile(r"\[\d+\]")
PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_\-*]+$")

GENERIC_SETTING_TOKENS = {
    "after",
    "apply",
    "arn",
    "before",
    "by",
    "configuration",
    "current",
    "default",
    "enabled",
    "field",
    "id",
    "name",
    "resource type",
    "rule",
    "rules",
    "setting",
    "settings",
    "status",
    "type",
    "value",
}

USER_FRIENDLY_TOKEN_MAP = {
    "apply_server_side_encryption_by_default": "default encryption",
    "auto_minor_version_upgrade": "minor version upgrade",
    "copy_tags_to_snapshot": "copy tags to snapshot",
    "deletion_protection": "deletion protection",
    "ebs_optimized": "EBS optimization",
    "egress": "egress rule",
    "enable_key_rotation": "key rotation",
    "enabled_cloudwatch_logs_exports": "CloudWatch logs export",
    "engine": "database engine",
    "iam_database_authentication_enabled": "IAM database authentication",
    "iam_instance_profile": "IAM instance profile",
    "ingress": "ingress rule",
    "kms_key_arn": "KMS key ARN",
    "kms_key_id": "KMS key",
    "lifecycle_rule": "lifecycle rule",
    "load_balancer_type": "load balancer type",
    "map_public_ip_on_launch": "public IP auto assign",
    "metadata_options": "instance metadata options",
    "monitoring": "detailed monitoring",
    "monitoring_interval": "monitoring interval",
    "monitoring_role_arn": "monitoring role",
    "multi_az": "Multi-AZ",
    "point_in_time_recovery": "point in time recovery",
    "policy": "key policy",
    "protocol": "protocol",
    "replication_configuration": "replication configuration",
    "resource_type": "resource type",
    "rule": "rule",
    "rules": "replication rules",
    "server_side_encryption": "server side encryption",
    "server_side_encryption_configuration": "server side encryption configuration",
    "ssl_policy": "TLS policy",
    "sse_algorithm": "encryption algorithm",
    "versioning": "versioning",
    "versioning_configuration": "versioning configuration",
}


AUTO_REMEDIABLE_CHECK_IDS = {
    "CKV_AWS_126",
    "CKV_AWS_79",
    "CKV_AWS_135",
    "CKV_AWS_7",
    "CKV_AWS_28",
    "CKV_AWS_119",
    "CKV_AWS_118",
    "CKV_AWS_129",
    "CKV_AWS_226",
    "CKV_AWS_161",
    "CKV_AWS_293",
    "CKV_AWS_157",
    "CKV2_AWS_60",
    "CKV_AWS_103",
    "CKV2_AWS_74",
    "CKV_AWS_21",
    "CKV2_AWS_61",
    "CKV_AWS_145",
    "CKV_AWS_149",
    "CKV_AWS_23",
    "CKV2_AWS_11",
    "3.7",
    "3.9",
    "4.1",
    "4.2",
    "4.3",
}


CHECK_EXPLANATIONS: dict[str, dict[str, Any]] = {
    "CKV_AWS_126": {
        "risk": ["EC2 상세 모니터링이 비활성화되어 성능 이상 징후를 빠르게 파악하기 어렵습니다."],
        "changes": [
            {"field": "monitoring", "before": "false or unset", "after": "true"},
        ],
        "impact": ["CloudWatch 상세 모니터링 비용이 증가할 수 있습니다."],
    },
    "CKV_AWS_79": {
        "risk": ["IMDSv1 허용 상태에서는 SSRF 등으로 metadata 접근 위험이 커질 수 있습니다."],
        "changes": [
            {"field": "metadata_options.http_tokens", "before": "optional or unset", "after": "required"},
            {"field": "metadata_options.http_endpoint", "before": "unset", "after": "enabled"},
        ],
        "impact": ["기존 IMDSv1 의존 스크립트가 있으면 점검이 필요합니다."],
    },
    "CKV_AWS_28": {
        "risk": ["DynamoDB 데이터 복구 시점 복원이 불가능할 수 있습니다."],
        "changes": [
            {"field": "point_in_time_recovery.enabled", "before": "false or unset", "after": "true"},
        ],
        "impact": ["복구 가능성은 높아지지만 운영 정책에 따라 비용이 증가할 수 있습니다."],
    },
    "CKV_AWS_135": {
        "risk": ["EBS 최적화가 비활성화되어 EC2의 디스크 I/O 성능이 제한될 수 있습니다."],
        "changes": [
            {"field": "ebs_optimized", "before": "false or unset", "after": "true"},
        ],
        "impact": ["인스턴스 타입에 따라 성능 특성과 비용이 달라질 수 있습니다."],
    },
    "CKV_AWS_7": {
        "risk": ["KMS 키 자동 회전이 비활성화되어 장기 키 사용 리스크가 커질 수 있습니다."],
        "changes": [
            {"field": "enable_key_rotation", "before": "false or unset", "after": "true"},
        ],
        "impact": ["키 운영 정책은 개선되지만 애플리케이션 영향은 거의 없습니다."],
    },
    "CKV_AWS_119": {
        "risk": ["DynamoDB 서버측 암호화가 미흡하면 저장 데이터 보호 수준이 낮아질 수 있습니다."],
        "changes": [
            {"field": "server_side_encryption.enabled", "before": "false or missing", "after": "true"},
            {"field": "server_side_encryption.kms_key_arn", "before": "missing or null", "after": "configured KMS key if available"},
        ],
        "impact": ["KMS 키 사용 시 권한과 운영 정책 검토가 필요할 수 있습니다."],
    },
    "CKV_AWS_145": {
        "risk": ["버킷 객체가 기본 암호화 없이 저장될 수 있습니다."],
        "changes": [
            {"field": "S3 default encryption", "before": "disabled or missing", "after": "enabled"},
        ],
        "impact": ["기존 데이터 처리 흐름에서 암호화 정책 검토가 필요할 수 있습니다."],
    },
    "CKV_AWS_103": {
        "risk": ["약한 TLS 정책 허용 시 구형 암호군 사용 위험이 있습니다."],
        "changes": [
            {"field": "ssl_policy", "before": "legacy TLS policy", "after": "ELBSecurityPolicy-TLS13-1-2-2021-06"},
        ],
        "impact": ["구형 클라이언트 호환성이 줄어들 수 있습니다."],
    },
    "CKV2_AWS_74": {
        "risk": ["약한 TLS 정책 허용 시 구형 암호군 사용 위험이 있습니다."],
        "changes": [
            {"field": "ssl_policy", "before": "legacy TLS policy", "after": "ELBSecurityPolicy-TLS13-1-2-2021-06"},
        ],
        "impact": ["구형 클라이언트 호환성이 줄어들 수 있습니다."],
    },
    "CKV_AWS_118": {
        "risk": ["RDS 상세 모니터링이 없어 운영 이상 징후를 놓칠 수 있습니다."],
        "changes": [
            {"field": "monitoring_interval", "before": "0 or unset", "after": "60"},
            {"field": "monitoring_role_arn", "before": "missing", "after": "enhanced monitoring role attached"},
        ],
        "impact": ["CloudWatch 모니터링 리소스와 IAM role이 추가됩니다."],
    },
    "CKV_AWS_129": {
        "risk": ["DB 로그 미수집 시 장애나 이상 행위를 추적하기 어렵습니다."],
        "changes": [
            {"field": "enabled_cloudwatch_logs_exports", "before": "missing or partial", "after": "[error, general, slowquery]"},
        ],
        "impact": ["로그 저장 비용이 증가할 수 있습니다."],
    },
    "CKV_AWS_226": {
        "risk": ["보안 패치가 포함된 마이너 업그레이드가 자동 반영되지 않을 수 있습니다."],
        "changes": [
            {"field": "auto_minor_version_upgrade", "before": "false or unset", "after": "true"},
        ],
        "impact": ["유지보수 시점에 자동 업그레이드가 발생할 수 있습니다."],
    },
    "CKV_AWS_161": {
        "risk": ["IAM DB 인증이 비활성화되어 자격 증명 관리가 단순 패스워드에 치우칠 수 있습니다."],
        "changes": [
            {"field": "iam_database_authentication_enabled", "before": "false or unset", "after": "true"},
        ],
        "impact": ["애플리케이션 인증 방식 검토가 필요할 수 있습니다."],
    },
    "CKV_AWS_293": {
        "risk": ["삭제 보호가 없으면 실수로 DB가 삭제될 수 있습니다."],
        "changes": [
            {"field": "deletion_protection", "before": "false or unset", "after": "true"},
        ],
        "impact": ["운영 중 수동 삭제 절차가 더 엄격해집니다."],
    },
    "CKV_AWS_157": {
        "risk": ["단일 AZ 구성에서는 장애 복원력이 낮습니다."],
        "changes": [
            {"field": "multi_az", "before": "false", "after": "true"},
        ],
        "impact": ["비용 증가와 배포 시간 증가가 있을 수 있습니다."],
    },
    "CKV2_AWS_60": {
        "risk": ["스냅샷에 리소스 태그가 복사되지 않아 운영 식별성이 떨어질 수 있습니다."],
        "changes": [
            {"field": "copy_tags_to_snapshot", "before": "false or unset", "after": "true"},
        ],
        "impact": ["스냅샷 태그 정책이 정리됩니다."],
    },
    "CKV_AWS_21": {
        "risk": ["버전 관리가 없으면 객체 롤백과 복구가 어렵습니다."],
        "changes": [
            {"field": "S3 versioning", "before": "disabled", "after": "enabled"},
        ],
        "impact": ["버전 저장으로 비용이 증가할 수 있습니다."],
    },
    "CKV2_AWS_61": {
        "risk": ["수명 주기 정책이 없으면 오래된 객체와 버전이 계속 누적될 수 있습니다."],
        "changes": [
            {"field": "S3 lifecycle rule", "before": "missing", "after": "default lifecycle enabled"},
        ],
        "impact": ["오래된 객체/버전이 자동 만료될 수 있습니다."],
    },
    "CKV_AWS_149": {
        "risk": ["Secrets Manager 시크릿이 KMS 키 없이 저장될 수 있습니다."],
        "changes": [
            {"field": "kms_key_id", "before": "AWS managed default or unset", "after": "customer-managed KMS key"},
        ],
        "impact": ["KMS 키 접근 권한 검토가 필요합니다."],
    },
    "CKV_AWS_23": {
        "risk": ["보안 그룹 규칙 설명이 없어 운영 추적성과 리뷰 품질이 떨어질 수 있습니다."],
        "changes": [
            {"field": "ingress.description", "before": "missing", "after": "managed description added"},
            {"field": "egress.description", "before": "missing", "after": "managed description added"},
        ],
        "impact": ["동작 변화는 거의 없고 가독성만 향상됩니다."],
    },
    "CKV2_AWS_11": {
        "risk": ["VPC Flow Log가 없어 네트워크 흐름 추적이 어렵습니다."],
        "changes": [
            {"field": "aws_flow_log", "before": "missing", "after": "created"},
            {"field": "aws_cloudwatch_log_group", "before": "missing", "after": "created"},
        ],
        "impact": ["로그 저장 비용과 IAM role이 추가됩니다."],
    },
    "3.1": {
        "risk": ["과도한 네트워크 허용 범위로 외부 노출 면적이 커질 수 있습니다."],
        "impact": ["허용 범위를 좁히면 정상 트래픽이 차단되지 않는지 검토가 필요합니다."],
    },
    "3.4": {
        "risk": ["불필요한 0.0.0.0/0 라우팅은 의도치 않은 인터넷 경로를 만들 수 있습니다."],
        "impact": ["경로를 제거하면 통신 단절이 발생할 수 있습니다."],
    },
    "3.5": {
        "risk": ["IGW 연결은 VPC를 인터넷과 직접 연결할 수 있습니다."],
        "impact": ["제거 시 공개 서비스 통신이 끊길 수 있습니다."],
    },
    "3.6": {
        "risk": ["NAT 경로는 private subnet의 외부 outbound 경로를 만듭니다."],
        "impact": ["제거 시 패치, 패키지 다운로드, 외부 API 호출이 실패할 수 있습니다."],
    },
    "3.7": {
        "risk": ["S3 접근 제어가 약하면 버킷 또는 객체가 외부에 노출될 수 있습니다."],
        "changes": [
            {"field": "public access block", "before": "missing or partial", "after": "fully enabled"},
        ],
        "impact": ["기존 공개 사용 사례가 있다면 접근이 차단될 수 있습니다."],
    },
    "3.9": {
        "risk": ["ALB 보안 헤더/보호 설정이 약하면 공격 표면이 넓어질 수 있습니다."],
        "changes": [
            {"field": "drop_invalid_header_fields", "before": "false or unset", "after": "true"},
            {"field": "enable_deletion_protection", "before": "false or unset", "after": "true"},
        ],
        "impact": ["운영 중 삭제 절차가 더 엄격해집니다."],
    },
    "4.1": {
        "risk": ["루트 EBS 볼륨이 암호화되지 않으면 저장 데이터 보호 수준이 낮아집니다."],
        "changes": [
            {"field": "root_block_device.encrypted", "before": "false or unset", "after": "true"},
        ],
        "impact": ["볼륨 재생성 또는 재배포 전략 검토가 필요할 수 있습니다."],
    },
    "4.2": {
        "risk": ["RDS 저장소 암호화가 없으면 데이터 보호 수준이 낮아집니다."],
        "changes": [
            {"field": "storage_encrypted", "before": "false", "after": "true"},
        ],
        "impact": ["기존 운영 DB에는 즉시 반영이 어려울 수 있습니다."],
    },
    "4.3": {
        "risk": ["S3 기본 암호화가 없으면 신규 객체가 평문으로 저장될 수 있습니다."],
        "changes": [
            {"field": "S3 default encryption", "before": "disabled or missing", "after": "AES256 or aws:kms"},
        ],
        "impact": ["암호화 정책과 KMS 사용 여부를 운영 기준에 맞춰 점검해야 합니다."],
    },
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file_obj:
        return json.load(file_obj)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file_obj:
        json.dump(data, file_obj, ensure_ascii=False, indent=2)


def extract_resource_type(resource_id: str | None) -> str:
    if not resource_id:
        return "unknown"
    return str(resource_id).split(".", 1)[0]


def extract_resource_name(finding: dict[str, Any]) -> str:
    entity_tags = finding.get("entity_tags")
    if isinstance(entity_tags, dict):
        name_tag = entity_tags.get("Name")
        if name_tag:
            return str(name_tag)

    resource = str(finding.get("resource") or "")
    if "." in resource:
        return resource.split(".")[-1]

    return resource or "unknown"


def normalize_status(result: str | None) -> str:
    value = str(result or "").upper()
    if value in {"PASSED", "FIXED"}:
        return "safe"
    return "vulnerable"


def stringify_details(details: Any) -> str:
    if details is None:
        return ""

    if isinstance(details, str):
        return details.strip()

    if isinstance(details, list):
        parts = [stringify_details(item) for item in details]
        return " / ".join(part for part in parts if part)

    if isinstance(details, dict):
        preferred_keys = (
            "message",
            "guide",
            "reason",
            "description",
            "current",
            "target",
        )
        parts: list[str] = []
        for key in preferred_keys:
            value = details.get(key)
            text = stringify_details(value)
            if text:
                parts.append(text)

        if parts:
            return " / ".join(parts)

        return json.dumps(details, ensure_ascii=False)

    return str(details).strip()


def normalize_description(finding: dict[str, Any]) -> str:
    for key in ("details", "short_description", "description", "check_name"):
        text = stringify_details(finding.get(key))
        if text:
            return text
    return "진단 결과 상세 설명이 제공되지 않았습니다."


def normalize_current_value(finding: dict[str, Any]) -> str:
    details_text = stringify_details(finding.get("details"))
    if details_text:
        return details_text

    evaluated_keys = ((finding.get("check_result") or {}).get("evaluated_keys")) or []
    if isinstance(evaluated_keys, list) and evaluated_keys:
        return ", ".join(compact_evaluated_key(item) for item in evaluated_keys if str(item).strip())

    return ""


def compact_evaluated_key(value: Any) -> str:
    text = str(value).strip()
    if not text:
        return ""

    text = INDEX_PATH_RE.sub("/", text)
    text = INLINE_INDEX_RE.sub("", text)
    text = re.sub(r"/{2,}", "/", text)
    return text.strip().strip("/")


def ordinal_label(index_text: str) -> str:
    try:
        index = int(index_text)
    except ValueError:
        return f"[{index_text}]"

    ordinals = {
        0: "첫 번째 항목",
        1: "두 번째 항목",
        2: "세 번째 항목",
        3: "네 번째 항목",
        4: "다섯 번째 항목",
    }
    return ordinals.get(index, f"{index + 1}번째 항목")


def prettify_setting_token(token: str) -> str:
    token = str(token).strip()
    if not token:
        return ""

    if token.startswith("[") and token.endswith("]"):
        return ordinal_label(token[1:-1])

    lowered = token.lower()
    if lowered in USER_FRIENDLY_TOKEN_MAP:
        return USER_FRIENDLY_TOKEN_MAP[lowered]

    return token.replace("_", " ")


def split_setting_tokens(value: Any) -> list[str]:
    text = stringify_details(value)
    if not text:
        return []

    tokens: list[str] = []
    for part in text.split(","):
        part = compact_evaluated_key(part)
        if not part:
            continue

        if looks_like_path_expression(part):
            path_tokens = [token for token in part.split("/") if token]
            for path_token in path_tokens:
                dot_tokens = [segment for segment in path_token.split(".") if segment]
                for dot_token in dot_tokens:
                    pretty = prettify_setting_token(dot_token)
                    if pretty:
                        tokens.append(pretty)
            continue

        if PATH_SEGMENT_RE.match(part):
            pretty = prettify_setting_token(part)
            if pretty:
                tokens.append(pretty)
            continue

        tokens.append(part)

    return tokens


def choose_setting_name_from_tokens(tokens: list[str], fallback: str) -> str:
    meaningful_tokens = [token for token in tokens if token and token != "*" and "항목" not in token]
    if not meaningful_tokens:
        return fallback

    for token in reversed(meaningful_tokens):
        if token.lower() not in GENERIC_SETTING_TOKENS:
            return token

    return meaningful_tokens[-1]


def is_generic_setting_name(name: str) -> bool:
    return not name or name.lower() in GENERIC_SETTING_TOKENS


def looks_like_path_expression(text: str) -> bool:
    candidate = str(text).strip()
    if not candidate or " " in candidate:
        return False
    if not any(marker in candidate for marker in ("/", ".", "[")):
        return False

    parts = [compact_evaluated_key(part) for part in candidate.split(",") if str(part).strip()]
    if not parts:
        return False

    for part in parts:
        path_tokens = [token for token in part.split("/") if token]
        if not path_tokens:
            return False

        for path_token in path_tokens:
            dot_tokens = [segment for segment in path_token.split(".") if segment]
            if not dot_tokens:
                return False

            for dot_token in dot_tokens:
                if not PATH_SEGMENT_RE.match(dot_token):
                    return False

    return True


def format_setting_for_display(value: Any) -> str:
    text = stringify_details(value)
    if not text:
        return ""

    parts = [part.strip() for part in text.split(",") if part.strip()]
    formatted_parts: list[str] = []

    for part in parts:
        normalized_part = compact_evaluated_key(part)

        if PATH_SEGMENT_RE.match(normalized_part):
            pretty = prettify_setting_token(normalized_part)
            formatted_parts.append(pretty or normalized_part)
            continue

        if not looks_like_path_expression(part):
            formatted_parts.append(part)
            continue

        normalized = normalized_part
        path_tokens = [token for token in normalized.split("/") if token]
        pretty_tokens: list[str] = []

        for path_token in path_tokens:
            dot_tokens = [segment for segment in path_token.split(".") if segment]
            for dot_token in dot_tokens:
                pretty = prettify_setting_token(dot_token)
                if pretty:
                    pretty_tokens.append(pretty)

        if pretty_tokens:
            formatted_parts.append(" > ".join(pretty_tokens))
        else:
            formatted_parts.append(part)

    if formatted_parts:
        return ", ".join(formatted_parts)

    return text


def infer_setting_name(value: Any, fallback: str = "설정") -> str:
    text = stringify_details(value)
    if not text:
        return fallback

    first_part = text.split(",")[0].strip()
    primary_name = choose_setting_name_from_tokens(split_setting_tokens(first_part), fallback)
    if not is_generic_setting_name(primary_name):
        return primary_name

    full_name = choose_setting_name_from_tokens(split_setting_tokens(text), fallback)
    return full_name


def add_display_field(fields: list[dict[str, Any]], label: str, value: Any) -> None:
    text = stringify_details(value)
    if not text:
        return
    fields.append({"label": label, "value": value})


def build_vulnerability_display_fields(
    finding: dict[str, Any],
    detected_setting_name: str,
    detected_current_setting: str,
    recommended_target_setting: str,
    auto_remediable: bool,
) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    add_display_field(fields, "리소스 ID", str(finding.get("resource") or ""))
    add_display_field(fields, "리소스 이름", extract_resource_name(finding))
    add_display_field(fields, "리소스 타입", extract_resource_type(finding.get("resource")))
    add_display_field(fields, "취약 항목", str(finding.get("check_name") or ""))
    add_display_field(fields, f"{detected_setting_name} 설정값", detected_current_setting)
    add_display_field(fields, f"{detected_setting_name} 권장값", recommended_target_setting)
    add_display_field(fields, "조치 방식", "자동 조치" if auto_remediable else "수동 조치")
    return fields


def build_change_display_fields(change: dict[str, Any]) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    add_display_field(fields, "항목", change.get("settingName") or change.get("field"))
    add_display_field(fields, change.get("currentSettingLabel") or "현재 설정값", change.get("currentSetting"))
    add_display_field(fields, change.get("changedSettingLabel") or "변경 후 설정값", change.get("changedSetting"))
    return fields


def infer_severity(finding: dict[str, Any]) -> str:
    raw_severity = finding.get("severity")
    if raw_severity:
        return str(raw_severity).lower()

    check_id = str(finding.get("check_id") or "").upper()
    check_name = str(finding.get("check_name") or "").lower()
    resource_type = extract_resource_type(finding.get("resource"))

    high_keywords = (
        "security group",
        "보안 그룹",
        "internet gateway",
        "인터넷 게이트웨이",
        "nat 게이트웨이",
        "route",
        "라우팅",
        "public access",
        "metadata service",
        "waf",
        "tls",
        "cipher",
    )
    medium_keywords = (
        "logging",
        "monitoring",
        "versioning",
        "encryption",
        "암호화",
        "backup",
        "rotation",
        "minor upgrades",
        "lifecycle",
        "flow logging",
    )

    if resource_type in {"aws_security_group", "aws_route_table", "aws_internet_gateway", "aws_nat_gateway"}:
        return "high"

    if any(keyword in check_name for keyword in high_keywords):
        return "high"

    if check_id.startswith(("CKV2_AWS_", "CKV_AWS_")) and any(keyword in check_name for keyword in medium_keywords):
        return "medium"

    if resource_type in {"aws_s3_bucket", "aws_db_instance", "aws_dynamodb_table", "aws_instance"}:
        return "medium"

    return "low"


def infer_remediation(finding: dict[str, Any]) -> str:
    check_name = str(finding.get("check_name") or "").lower()
    resource_type = extract_resource_type(finding.get("resource"))
    guideline = finding.get("guideline")

    if "metadata service" in check_name:
        return "EC2 인스턴스에서 IMDSv2만 허용하도록 metadata_options.http_tokens=required 로 설정하세요."
    if "security group" in check_name or "보안 그룹" in check_name:
        return "보안 그룹 규칙을 재검토해 0.0.0.0/0 전체 개방, 모든 포트 허용, 불필요한 egress 규칙을 제거하세요."
    if "route" in check_name or "라우팅" in check_name:
        return "라우팅 테이블에서 0.0.0.0/0 경로가 필요한 서브넷에만 존재하도록 제한하고, 불필요한 인터넷 경로는 제거하세요."
    if "logging" in check_name:
        return "해당 리소스의 접근 로그 또는 운영 로그 수집을 활성화하세요."
    if "monitoring" in check_name:
        return "상세 모니터링 또는 강화 모니터링을 활성화하세요."
    if "versioning" in check_name:
        return "버킷 버저닝을 활성화해 데이터 복구 가능성을 확보하세요."
    if "rotation" in check_name:
        return "회전(rotation) 기능을 활성화하거나 자동 교체 정책을 설정하세요."
    if "backup" in check_name or "recovery" in check_name:
        return "백업 또는 point-in-time recovery 기능을 활성화하세요."
    if "encryption" in check_name or "암호화" in check_name:
        if resource_type == "aws_s3_bucket":
            return "S3 기본 암호화를 활성화하고 가능하면 KMS CMK를 사용하세요."
        if resource_type == "aws_db_instance":
            return "RDS 저장소 암호화를 활성화하고 필요 시 KMS 키를 명시적으로 지정하세요."
        return "리소스 암호화 설정을 활성화하고 필요 시 KMS 기반 암호화를 적용하세요."
    if "waf" in check_name:
        return "WAF 정책과 로깅 설정을 활성화하고 ALB 또는 공개 엔드포인트에 올바르게 연결하세요."
    if "iam role" in check_name:
        return "EC2 또는 대상 리소스에 필요한 최소 권한 IAM Role을 연결하세요."

    if guideline:
        return f"가이드라인을 참고해 설정을 보완하세요: {guideline}"

    return "진단 결과를 검토해 보안상 안전한 값으로 설정을 수정하세요."


def infer_suggested_value(finding: dict[str, Any]) -> str:
    check_name = str(finding.get("check_name") or "").lower()
    resource_type = extract_resource_type(finding.get("resource"))

    if "metadata service" in check_name:
        return "metadata_options.http_tokens=required"
    if "security group" in check_name or "보안 그룹" in check_name:
        return "0.0.0.0/0 및 전체 포트 허용 제거"
    if "route" in check_name or "라우팅" in check_name:
        return "필요한 서브넷에만 0.0.0.0/0 라우팅 허용"
    if "logging" in check_name:
        return "logging enabled"
    if "monitoring" in check_name:
        return "monitoring enabled"
    if "versioning" in check_name:
        return "versioning enabled"
    if "backup" in check_name or "recovery" in check_name:
        return "backup / point-in-time recovery enabled"
    if "rotation" in check_name:
        return "rotation enabled"
    if "encryption" in check_name or "암호화" in check_name:
        if resource_type == "aws_s3_bucket":
            return "SSE-KMS or SSE-S3 enabled"
        return "encryption enabled"
    if "iam role" in check_name:
        return "least-privilege IAM role attached"

    return ""


def build_vulnerability_id(finding: dict[str, Any]) -> str:
    check_id = str(finding.get("check_id") or "unknown")
    resource = str(finding.get("resource") or "unknown")
    return f"{check_id}::{resource}"


def build_why_vulnerable(finding: dict[str, Any]) -> dict[str, Any]:
    check_id = str(finding.get("check_id") or "")
    details = stringify_details(finding.get("details"))
    meta = CHECK_EXPLANATIONS.get(check_id, {})

    summary = details or normalize_description(finding)
    current_state = [details] if details else []
    if not current_state:
        current_value = normalize_current_value(finding)
        if current_value:
            current_state.append(current_value)

    risk = meta.get("risk")
    if not risk:
        risk = ["현재 설정이 보안 기준에 미달해 공격 표면 또는 운영 리스크가 증가할 수 있습니다."]

    return {
        "summary": summary,
        "currentState": current_state,
        "risk": risk,
    }


def build_default_change_preview(finding: dict[str, Any]) -> list[dict[str, str]]:
    suggested = infer_suggested_value(finding)
    current = normalize_current_value(finding) or "current configuration"
    if not suggested:
        suggested = "security-hardened configuration applied"
    return [
        {
            "field": "configuration",
            "before": current,
            "after": suggested,
        }
    ]


def enrich_change_fields(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for change in changes:
        if not isinstance(change, dict):
            continue

        current_setting = format_setting_for_display(change.get("before", ""))
        changed_setting = format_setting_for_display(change.get("after", ""))
        setting_name = infer_setting_name(change.get("field") or change.get("before"), "설정")

        enriched_change = dict(change)
        enriched_change["settingName"] = setting_name
        enriched_change["currentSettingLabel"] = f"{setting_name} 현재 설정값"
        enriched_change["changedSettingLabel"] = f"{setting_name} 변경 후 설정값"
        enriched_change["currentSetting"] = current_setting
        enriched_change["changedSetting"] = changed_setting
        enriched_change["displayFields"] = build_change_display_fields(enriched_change)
        enriched.append(enriched_change)

    return enriched


def build_remediation_preview(finding: dict[str, Any]) -> dict[str, Any]:
    check_id = str(finding.get("check_id") or "")
    auto_remediable = check_id in AUTO_REMEDIABLE_CHECK_IDS
    meta = CHECK_EXPLANATIONS.get(check_id, {})
    changes = meta.get("changes") or build_default_change_preview(finding)
    if auto_remediable and not changes:
        changes = build_default_change_preview(finding)
    changes = enrich_change_fields(changes)

    return {
        "mode": "auto" if auto_remediable else "manual",
        "summary": infer_remediation(finding),
        "changes": changes,
        "impact": meta.get("impact", []),
    }


def build_remediation_form(finding: dict[str, Any]) -> dict[str, Any] | None:
    check_id = str(finding.get("check_id") or "")
    resource = str(finding.get("resource") or "")

    if check_id in {"CKV_AWS_382", "CKV_AWS_260", "3.1"}:
        default_port = 443 if resource.endswith(".alb") else 8080 if resource.endswith(".app") else 3306 if resource.endswith(".db") else None
        default_fields = [
            {"key": "cidr", "inputType": "cidr", "required": False, "default": "0.0.0.0/0"},
            {"key": "fromPort", "inputType": "port", "required": False, "default": default_port},
            {"key": "toPort", "inputType": "port", "required": False, "default": default_port},
            {"key": "protocol", "inputType": "select", "required": True, "options": ["tcp", "udp", "icmp", "all"], "default": "tcp"},
            {"key": "direction", "inputType": "select", "required": True, "options": ["ingress", "egress"], "default": "ingress"},
            {"key": "allowedSourceType", "inputType": "select", "required": True, "options": ["cidr", "security_group"], "default": "cidr"},
            {"key": "allowedSourceSecurityGroupId", "inputType": "resourceRef", "required": False},
        ]
        return {"type": "network_rule", "fields": default_fields}

    if check_id in {"CKV_AWS_130"}:
        return {
            "type": "subnet_public_ip_setting",
            "fields": [
                {"key": "mapPublicIpOnLaunch", "inputType": "boolean", "required": True, "default": False},
                {"key": "decisionNote", "inputType": "text", "required": False},
            ],
        }

    if check_id in {"CKV_AWS_192", "CKV2_AWS_76"}:
        return {
            "type": "waf_managed_rule_selection",
            "fields": [
                {
                    "key": "managedRuleGroup",
                    "inputType": "select",
                    "required": True,
                    "options": [
                        "AWSManagedRulesKnownBadInputsRuleSet",
                        "AWSManagedRulesCommonRuleSet",
                        "AWSManagedRulesAnonymousIpList",
                    ],
                    "default": "AWSManagedRulesKnownBadInputsRuleSet",
                },
                {"key": "webAclArn", "inputType": "arn", "required": False},
                {"key": "associateToResourceArn", "inputType": "arn", "required": False},
                {"key": "decisionNote", "inputType": "text", "required": False},
            ],
        }

    if check_id in {"CKV2_AWS_31"}:
        return {
            "type": "waf_logging_configuration",
            "fields": [
                {
                    "key": "logDestinationType",
                    "inputType": "select",
                    "required": True,
                    "options": ["cloudwatch", "s3", "kinesis_firehose"],
                    "default": "cloudwatch",
                },
                {"key": "logDestinationArn", "inputType": "arn", "required": True},
                {"key": "redactedFields", "inputType": "multiselect", "required": False, "options": ["uri_path", "query_string", "single_header.authorization"]},
                {"key": "decisionNote", "inputType": "text", "required": False},
            ],
        }

    if check_id in {"CKV2_AWS_41"}:
        return {
            "type": "iam_instance_profile_attachment",
            "fields": [
                {"key": "instanceProfileArn", "inputType": "arn", "required": True},
                {"key": "roleArn", "inputType": "arn", "required": False},
                {"key": "decisionNote", "inputType": "text", "required": False},
            ],
        }

    if check_id in {"CKV2_AWS_64"}:
        return {
            "type": "kms_policy_document",
            "fields": [
                {"key": "policyDocument", "inputType": "jsonPolicy", "required": True},
                {"key": "decisionNote", "inputType": "text", "required": False},
            ],
        }

    if check_id in {"CKV2_AWS_62"}:
        return {
            "type": "s3_event_notification",
            "fields": [
                {
                    "key": "targetType",
                    "inputType": "select",
                    "required": True,
                    "options": ["sqs", "sns", "lambda"],
                    "default": "sqs",
                },
                {"key": "targetArn", "inputType": "arn", "required": True},
                {
                    "key": "events",
                    "inputType": "multiselect",
                    "required": True,
                    "options": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*", "s3:ObjectRestore:*"],
                },
                {"key": "filterPrefix", "inputType": "text", "required": False},
                {"key": "filterSuffix", "inputType": "text", "required": False},
            ],
        }

    if check_id in {"CKV_AWS_18"}:
        return {
            "type": "s3_access_logging",
            "fields": [
                {"key": "targetBucket", "inputType": "resourceRef", "required": True},
                {"key": "targetPrefix", "inputType": "text", "required": False},
                {"key": "decisionNote", "inputType": "text", "required": False},
            ],
        }

    if check_id in {"CKV_AWS_144"}:
        return {
            "type": "s3_replication_configuration",
            "fields": [
                {"key": "destinationBucketArn", "inputType": "arn", "required": True},
                {"key": "replicationRoleArn", "inputType": "arn", "required": True},
                {"key": "replicaKmsKeyArn", "inputType": "arn", "required": False},
                {"key": "replicateDeleteMarkers", "inputType": "boolean", "required": False, "default": True},
                {"key": "decisionNote", "inputType": "text", "required": False},
            ],
        }

    if check_id in {"CKV2_AWS_57"}:
        return {
            "type": "secret_rotation_configuration",
            "fields": [
                {"key": "rotationLambdaArn", "inputType": "arn", "required": True},
                {"key": "rotationIntervalDays", "inputType": "number", "required": True, "default": 30},
                {"key": "rotationScheduleExpression", "inputType": "text", "required": False},
                {"key": "decisionNote", "inputType": "text", "required": False},
            ],
        }

    if check_id in {"3.5", "3.6"}:
        return {
            "type": "keep_remove_decision",
            "fields": [
                {"key": "decision", "inputType": "radio", "required": True, "options": ["keep", "remove"], "default": "keep"},
                {"key": "replacementTarget", "inputType": "resourceRef", "required": False},
            ],
        }

    if check_id in {"3.4"}:
        return {
            "type": "route_table_update",
            "fields": [
                {"key": "cidr", "inputType": "cidr", "required": True, "default": "0.0.0.0/0"},
                {
                    "key": "targetType",
                    "inputType": "select",
                    "required": True,
                    "options": ["internet_gateway", "nat_gateway", "transit_gateway", "remove_route"],
                    "default": "nat_gateway",
                },
                {"key": "targetResourceId", "inputType": "resourceRef", "required": False},
                {"key": "decisionNote", "inputType": "text", "required": False},
            ],
        }

    if check_id not in AUTO_REMEDIABLE_CHECK_IDS:
        return {
            "type": "manual_review",
            "fields": [
                {"key": "decisionNote", "inputType": "text", "required": False},
            ],
        }

    return None


def transform_finding(finding: dict[str, Any]) -> dict[str, Any]:
    check_result = finding.get("check_result") or {}
    resource_id = str(finding.get("resource") or "")
    file_path = finding.get("repo_file_path") or finding.get("file_path")
    check_id = str(finding.get("check_id") or "")
    status = normalize_status(check_result.get("result"))
    auto_remediable = check_id in AUTO_REMEDIABLE_CHECK_IDS
    current_value = normalize_current_value(finding)
    suggested_value = infer_suggested_value(finding)
    detected_current_setting = format_setting_for_display(current_value)
    recommended_target_setting = format_setting_for_display(suggested_value)
    detected_setting_name = infer_setting_name(current_value, "탐지 설정")

    return {
        "id": build_vulnerability_id(finding),
        "resourceId": resource_id,
        "resourceName": extract_resource_name(finding),
        "resourceType": extract_resource_type(resource_id),
        "severity": infer_severity(finding),
        "title": str(finding.get("check_name") or "Unnamed finding"),
        "description": normalize_description(finding),
        "remediation": infer_remediation(finding),
        "status": status,
        "currentValue": current_value,
        "suggestedValue": suggested_value,
        "detectedSettingName": detected_setting_name,
        "detectedCurrentSettingLabel": f"{detected_setting_name} 현재 설정값",
        "detectedCurrentSetting": detected_current_setting,
        "recommendedTargetSettingLabel": f"{detected_setting_name} 권장 설정값",
        "recommendedTargetSetting": recommended_target_setting,
        "displayFields": build_vulnerability_display_fields(
            finding,
            detected_setting_name,
            detected_current_setting,
            recommended_target_setting,
            auto_remediable,
        ),
        "filePath": file_path,
        "fileLineRange": finding.get("file_line_range"),
        "guideline": finding.get("guideline"),
        "source": finding.get("source"),
        "checkId": check_id,
        "autoRemediable": auto_remediable,
        "whyVulnerable": build_why_vulnerable(finding),
        "remediationPreview": build_remediation_preview(finding),
        "remediationForm": build_remediation_form(finding),
    }


def transform_merged_findings(data: dict[str, Any]) -> dict[str, Any]:
    merged_findings = data.get("merged_findings") or []
    vulnerabilities: list[dict[str, Any]] = []

    for finding in merged_findings:
        if not isinstance(finding, dict):
            continue

        transformed = transform_finding(finding)
        if transformed.get("status") != "vulnerable":
            continue

        vulnerabilities.append(transformed)

    return {
        "count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


def build_output_path(input_path: Path) -> Path:
    if input_path.name == "step3_merged_fixed.json":
        return input_path.with_name("frontend_vulnerabilities_fixed.json")
    return input_path.with_name("frontend_vulnerabilities.json")


def find_latest_diag_run_dir(base_dir: Path) -> Path | None:
    candidates = [
        path
        for path in base_dir.iterdir()
        if path.is_dir() and path.name.startswith("diag_run_")
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def find_latest_remedy_run_dir(base_dir: Path) -> Path | None:
    candidates = [
        path
        for path in base_dir.iterdir()
        if path.is_dir() and path.name.startswith("remedy_run_")
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def resolve_latest_diag_merged_result(base_dir: Path) -> Path | None:
    latest_run_dir = find_latest_diag_run_dir(base_dir)
    if latest_run_dir is None:
        return None

    summary_path = latest_run_dir / "diagnosis_summary.json"
    if summary_path.exists():
        try:
            summary = load_json(summary_path)
        except Exception:
            summary = {}

        artifacts = summary.get("artifacts") if isinstance(summary, dict) else {}
        merged_path = artifacts.get("step3_merged") if isinstance(artifacts, dict) else None
        if merged_path:
            candidate = Path(str(merged_path))
            if candidate.exists():
                return candidate

    fallback = latest_run_dir / "step2_merged_source.json"
    if fallback.exists():
        return fallback
    return None


def resolve_latest_remedy_merged_result(base_dir: Path) -> Path | None:
    latest_run_dir = find_latest_remedy_run_dir(base_dir)
    if latest_run_dir is None:
        return None

    summary_path = latest_run_dir / "remediation_summary.json"
    if summary_path.exists():
        try:
            summary = load_json(summary_path)
        except Exception:
            summary = {}

        artifacts = summary.get("artifacts") if isinstance(summary, dict) else {}
        merged_path = artifacts.get("step3_merged_fixed") if isinstance(artifacts, dict) else None
        if merged_path:
            candidate = Path(str(merged_path))
            if candidate.exists():
                return candidate

    fallback = latest_run_dir / "step3_merged_fixed.json"
    if fallback.exists():
        return fallback
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Transform merged diagnosis findings into frontend vulnerability DTOs."
    )
    parser.add_argument(
        "--mode",
        choices=("diag", "remedy"),
        default="diag",
        help="Auto-detection target when input is omitted. diag=latest diag_run_*, remedy=latest remedy_run_*",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Path to merged findings JSON. If omitted, the latest run for the selected mode is used.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output JSON path. Default: frontend_vulnerabilities.json next to input file.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.input:
        input_path = Path(args.input)
    else:
        if args.mode == "remedy":
            latest_path = resolve_latest_remedy_merged_result(BASE_DIR)
        else:
            latest_path = resolve_latest_diag_merged_result(BASE_DIR)
        if latest_path is None:
            if args.mode == "remedy":
                raise FileNotFoundError("Could not find a latest remedy_run_*/step3_merged_fixed.json automatically.")
            raise FileNotFoundError("Could not find a latest diag_run_*/step2_merged_source.json automatically.")
        input_path = latest_path

    output_path = Path(args.output) if args.output else build_output_path(input_path)

    data = load_json(input_path)
    transformed = transform_merged_findings(data)
    write_json(output_path, transformed)

    print(f"[INFO] Mode: {args.mode}")
    print(f"[INFO] Latest auto-detection: {'enabled' if not args.input else 'disabled'}")
    print(f"[INFO] Input: {input_path}")
    print(f"[INFO] Output: {output_path}")
    print(f"[INFO] Vulnerabilities: {transformed['count']}")


if __name__ == "__main__":
    main()
