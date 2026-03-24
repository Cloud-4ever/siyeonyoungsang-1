from __future__ import annotations

# Embedded from diagnosis.py
import datetime
import json
import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TF_DIR = os.path.join(BASE_DIR, "source_tf")


# ==========================================
# 1. Helper 함수: 결과 형식 생성
# ==========================================
def create_finding(check_code, check_name, res_type, res_name, status, details):
    return {
        "check_code": check_code,
        "check_name": check_name,
        "resource_type": res_type,
        "resource_name": res_name,
        "status": status,
        "severity": "HIGH" if status == "vulnerable" else "INFO",
        "details": details
    }


def split_resource_identifier(resource):
    if not isinstance(resource, str) or not resource:
        return "", ""

    parts = resource.split(".", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return resource, ""


# ==========================================
# 2. JSON 로드 / 리소스 추출
# ==========================================
def load_plan(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {filepath} 파일을 찾을 수 없습니다.")
        return None
    except json.JSONDecodeError:
        print(f"Error: {filepath} 파일이 올바른 JSON 형식이 아닙니다.")
        return None


def get_valid_resources(plan_data):
    valid_resources = []

    for res in plan_data.get("resource_changes", []):
        actions = res.get("change", {}).get("actions", [])
        after_vals = res.get("change", {}).get("after")

        if "delete" in actions or after_vals is None:
            continue

        valid_resources.append(res)

    return valid_resources


# ==========================================
# 3. 공통 보조 함수
# ==========================================
def _collect_all_config_resources(module_block):
    """
    configuration.root_module + child_modules까지 재귀적으로 순회하여
    모든 resources를 평탄화해서 반환
    """
    results = []

    if not isinstance(module_block, dict):
        return results

    for resource in module_block.get("resources", []):
        if isinstance(resource, dict):
            results.append(resource)

    for child in module_block.get("module_calls", {}).values():
        module = child.get("module")
        if isinstance(module, dict):
            results.extend(_collect_all_config_resources(module))

    for child_module in module_block.get("child_modules", []):
        if isinstance(child_module, dict):
            results.extend(_collect_all_config_resources(child_module))

    return results


def _extract_subnet_refs_from_configuration(plan_data, address):
    """
    configuration 정보에서 aws_db_subnet_group의 subnet_ids 참조를 찾아
    aws_subnet.xxx 형태로 반환
    """
    root_module = plan_data.get("configuration", {}).get("root_module", {})
    all_config_resources = _collect_all_config_resources(root_module)

    for resource in all_config_resources:
        if resource.get("address") != address:
            continue

        subnet_expr = resource.get("expressions", {}).get("subnet_ids", {})
        refs = subnet_expr.get("references", [])

        subnet_refs = []
        for ref in refs:
            if not isinstance(ref, str):
                continue

            match = re.match(r"^(aws_subnet\.[A-Za-z0-9_\-]+)\.(?:id|arn)$", ref)
            if match:
                subnet_refs.append(match.group(1))
                continue

            if re.match(r"^aws_subnet\.[A-Za-z0-9_\-]+$", ref):
                subnet_refs.append(ref)

        unique_refs = []
        for subnet_ref in subnet_refs:
            if subnet_ref not in unique_refs:
                unique_refs.append(subnet_ref)

        return unique_refs

    return []


def _build_subnet_az_map(resources):
    """
    resource_changes 안의 aws_subnet 리소스에서 address -> availability_zone 매핑 생성
    """
    subnet_az_map = {}

    for res in resources:
        if res.get("type") != "aws_subnet":
            continue

        address = res.get("address")
        after = res.get("change", {}).get("after", {}) or {}
        az = after.get("availability_zone")

        if address and az:
            subnet_az_map[address] = az

    return subnet_az_map


def _get_db_subnet_refs(plan_data, res):
    """
    aws_db_subnet_group에서 subnet_ids를 추출.
    1차: after.subnet_ids
    2차: configuration expressions.references
    """
    after = res.get("change", {}).get("after", {}) or {}
    subnet_ids = after.get("subnet_ids")

    # after.subnet_ids 안에 aws_subnet.xxx 형태가 직접 들어있는 경우
    if isinstance(subnet_ids, list) and subnet_ids:
        subnet_refs = []
        for subnet_id in subnet_ids:
            if isinstance(subnet_id, str) and subnet_id.startswith("aws_subnet."):
                subnet_refs.append(subnet_id)

        if subnet_refs:
            unique_refs = []
            for subnet_ref in subnet_refs:
                if subnet_ref not in unique_refs:
                    unique_refs.append(subnet_ref)
            return unique_refs

    # configuration 쪽 참조식에서 추출
    return _extract_subnet_refs_from_configuration(plan_data, res.get("address", ""))


# ==========================================
# 4. 개별 진단 함수
# ==========================================
def check_3_1_sg(resources):
    """
    3.1 보안 그룹 인/아웃바운드 ANY 설정 관리 점검 
    """
    findings = []
    
    for res in resources:
        res_type = res.get('type')
        res_name = res.get('name')
        after = res.get('change', {}).get('after', {})

        # 1. 검사할 룰(Rule)들을 담을 임시 리스트
        rules_to_check = []

        # 케이스 1: aws_security_group (인라인 룰 형태)
        if res_type == 'aws_security_group':
            for r_type in ['ingress', 'egress']:
                # rule_data가 None일 수 있으므로 빈 리스트([])로 방어 로직 처리
                for rule in (after.get(r_type) or []):
                    rules_to_check.append((r_type, rule))
                    
        # 케이스 2: aws_security_group_rule (독립 리소스 형태)
        elif res_type == 'aws_security_group_rule':
            r_type = after.get('type', 'unknown')
            rules_to_check.append((r_type, after))
        else:
            continue

        # 2. 모아진 룰들에 대해 일괄 검사 진행
        for rule_type, rule_data in rules_to_check:
            cidr_blocks = rule_data.get('cidr_blocks') or []
            ipv6_cidr_blocks = rule_data.get('ipv6_cidr_blocks') or []
            
            from_port = rule_data.get('from_port')
            to_port = rule_data.get('to_port')
            protocol = rule_data.get('protocol')

            # 1단계: IP 대역이 ANY (0.0.0.0/0 또는 ::/0) 인지 확인
            is_any_ip = ('0.0.0.0/0' in cidr_blocks) or ('::/0' in ipv6_cidr_blocks)

            if is_any_ip:
                # 2단계: 포트/프로토콜이 ANY (모든 트래픽) 인지 확인
                # 프로토콜이 "-1" 이거나, from_port 0 ~ to_port 0 이면 모든 포트 오픈을 의미
                is_any_port = str(protocol) == '-1' or (str(from_port) == '0' and str(to_port) == '0')

                if is_any_port:
                    details = f"[{rule_type.upper()}] 위험: 출발지/목적지가 ANY(0.0.0.0/0)이며 모든 포트가 개방되어 있습니다."
                    findings.append(create_finding(
                        check_code="3.1", 
                        check_name="보안 그룹 인/아웃바운드 ANY 설정 관리", 
                        res_type=res_type, 
                        res_name=res_name, 
                        status="vulnerable", 
                        details=details
                    ))
                    # 현재 룰에서 취약점이 발견되었으므로 다음 룰 검사로 넘어감
                    continue

    return findings

def check_3_2_sg(resources):
    """
    3.2 보안 그룹 인/아웃바운드 불필요 정책 관리 점검
    """
    findings = []
    
    # 외부에 ANY(0.0.0.0/0)로 절대 열려있으면 안 되는 관리 및 DB 포트
    DANGEROUS_PORTS = {
        20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet",
        3389: "RDP", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"
    }
    
    for res in resources:
        res_type = res.get('type')
        res_name = res.get('name')
        after = res.get('change', {}).get('after', {})

        # 1. 검사할 룰(Rule)들을 담을 임시 리스트
        rules_to_check = []

        if res_type == 'aws_security_group':
            for r_type in ['ingress', 'egress']:
                for rule in (after.get(r_type) or []):
                    rules_to_check.append((r_type, rule))
                    
        elif res_type == 'aws_security_group_rule':
            r_type = after.get('type', 'unknown')
            rules_to_check.append((r_type, after))
        else:
            continue

        # 2. 모아진 룰들에 대해 일괄 검사 진행
        for rule_type, rule_data in rules_to_check:
            cidr_blocks = rule_data.get('cidr_blocks') or []
            ipv6_cidr_blocks = rule_data.get('ipv6_cidr_blocks') or []
            
            from_port = rule_data.get('from_port')
            to_port = rule_data.get('to_port')
            protocol = rule_data.get('protocol')

            # IP 대역이 ANY (0.0.0.0/0 또는 ::/0) 인지 확인
            is_any_ip = ('0.0.0.0/0' in cidr_blocks) or ('::/0' in ipv6_cidr_blocks)
            if not is_any_ip:
                continue

            # 3.1에서 걸러지는 '모든 포트 오픈'은 패스 (중복 알람 방지)
            if str(protocol) == '-1' or (str(from_port) == '0' and str(to_port) == '0'):
                continue
            
            # 포트 번호 추출 (숫자가 아닌 예외 값 처리)
            try:
                f_port = int(from_port)
                t_port = int(to_port)
            except (ValueError, TypeError):
                continue

            # 지정된 포트 범위 내에 위험 포트가 포함되어 있는지 검사
            exposed_ports = []
            for d_port, service_name in DANGEROUS_PORTS.items():
                if f_port <= d_port <= t_port:
                    exposed_ports.append(f"{d_port}({service_name})")

            # 위험 포트가 발견되면 vulnerable 처리
            if exposed_ports:
                exposed_str = ", ".join(exposed_ports)
                details = f"[{rule_type.upper()}] 위험: ANY(0.0.0.0/0)로 외부 노출이 금지된 포트 [{exposed_str}] 가 개방되어 있습니다."
                findings.append(create_finding("3.2", "보안 그룹 인/아웃바운드 불필요 정책 관리", res_type, res_name, "vulnerable", details))

    return findings

def check_3_4_route_table(resources):
    """
    3.4 라우팅 테이블 정책 관리 점검
    """
    findings = []

    def has_approved_exception_tag(after_dict, check_code):
        if not isinstance(after_dict, dict):
            return False
        tags = after_dict.get("tags")
        if not isinstance(tags, dict):
            return False
        tag_key = f"SecurityException{check_code.replace('.', '_')}"
        tag_value = str(tags.get(tag_key, "")).strip().lower()
        return tag_value in {"approved", "true", "pass"}

    def get_target_info(route_dict, unknown_dict=None):
        target_keys = [
            'gateway_id', 'nat_gateway_id', 'transit_gateway_id', 
            'vpc_peering_connection_id', 'network_interface_id', 'egress_only_gateway_id'
        ]
        
        # 1. after 블록에서 값이 확정되어 있는지(빈 문자열이 아닌지) 확인
        for key in target_keys:
            if route_dict.get(key):
                return route_dict.get(key)
                
        # 2. 값이 없다면 after_unknown 블록에서 "생성 예정"인 키가 있는지 확인
        if unknown_dict and isinstance(unknown_dict, dict):
            for key in target_keys:
                if unknown_dict.get(key) is True:
                    return f"(생성 후 결정: {key})"
                    
        return "Unknown Target"


    for res in resources:
        res_type = res.get('type')
        res_name = res.get('name')
        change = res.get('change', {})
        
        after = change.get('after', {})
        after_unknown = change.get('after_unknown', {})

        # 케이스 1: aws_route_table (인라인)
        if res_type == 'aws_route_table':
            if has_approved_exception_tag(after, "3.4"):
                continue
            routes = after.get('route') or []
            
            # unknown 정보가 들어있는 배열을 안전하게 추출
            unknown_routes = after_unknown.get('route') if isinstance(after_unknown, dict) else []
            if not isinstance(unknown_routes, list):
                unknown_routes = []

            for idx, route in enumerate(routes):
                dest_cidr = route.get('destination_cidr_block') or route.get('cidr_block')
                dest_ipv6 = route.get('destination_ipv6_cidr_block') or route.get('ipv6_cidr_block')

                if dest_cidr == '0.0.0.0/0' or dest_ipv6 == '::/0':
                    # 인덱스(idx)를 맞춰서 해당하는 unknown_route를 찾음
                    u_route = unknown_routes[idx] if idx < len(unknown_routes) else None
                    target = get_target_info(route, u_route)
                    
                    details = f"위험: 목적지가 ANY({dest_cidr or dest_ipv6})인 라우팅 정책이 존재합니다. (타깃: {target})"
                    if 'igw' in str(target) or 'gateway_id' in str(target) or 'nat' in str(target):
                        details += " *단, 아웃바운드 통신이 명시적으로 필요한 서브넷(IGW/NAT)인 경우 예외(PASS) 처리 가능합니다."
                        
                    findings.append(create_finding("3.4", "라우팅 테이블 정책 관리", res_type, res_name, "vulnerable", details))

        # 케이스 2: aws_route (독립)
        elif res_type == 'aws_route':
            dest_cidr = after.get('destination_cidr_block') or after.get('cidr_block')
            dest_ipv6 = after.get('destination_ipv6_cidr_block') or after.get('ipv6_cidr_block')

            if dest_cidr == '0.0.0.0/0' or dest_ipv6 == '::/0':
                # 독립 리소스는 after_unknown 전체를 바로 넘기면 됨
                target = get_target_info(after, after_unknown)
                
                details = f"위험: 목적지가 ANY({dest_cidr or dest_ipv6})인 라우팅 정책이 존재합니다. (타깃: {target})"
                if 'igw' in str(target) or 'gateway_id' in str(target) or 'nat' in str(target):
                    details += " *단, 아웃바운드 통신이 명시적으로 필요한 서브넷(IGW/NAT)인 경우 예외(PASS) 처리 가능합니다."

                findings.append(create_finding("3.4", "라우팅 테이블 정책 관리", res_type, res_name, "vulnerable", details))

    return findings

def check_3_5_internet_gateway(resources):
    """
    3.5 인터넷 게이트웨이 연결 관리 점검 
    """
    findings = []

    for res in resources:
        res_type = res.get('type')
        if res_type != 'aws_internet_gateway':
            continue

        res_name = res.get('name')
        
        # 💡 추가 단서 1: Terraform 코드상의 정확한 위치 (예: aws_internet_gateway.main)
        res_address = res.get('address', 'Unknown Address')
        
        change = res.get('change', {})
        after = change.get('after') or {}
        after_unknown = change.get('after_unknown') or {}
        tags = after.get('tags') or {}
        if str(tags.get("SecurityException3_5", "")).strip().lower() in {"approved", "true", "pass"}:
            continue

        # 💡 추가 단서 2: Name 태그 추출
        tags = after.get('tags') or {}
        tag_name = tags.get('Name', '태그 미지정')

        # VPC ID 추출 (기존 로직 유지)
        vpc_id = after.get('vpc_id')
        if not vpc_id:
            if isinstance(after_unknown, dict) and after_unknown.get('vpc_id') is True:
                vpc_id = "(생성 후 결정)"
            else:
                vpc_id = "Unknown VPC"
        
        # 세부 정보
        details_dict = {
            "message": "인터넷 게이트웨이(IGW) 생성이 감지되었습니다. 확인이 필요합니다.",
            "code_address": res_address,
            "resource_tag_name": tag_name,
            "target_vpc": vpc_id,
            "guide": f"해당 IGW({tag_name})가 연결되는 VPC가 완전한 폐쇄망(Private)으로 설계된 곳이라면 삭제해야 합니다."
        }

        findings.append(create_finding(
            check_code="3.5", 
            check_name="인터넷 게이트웨이 연결 관리", 
            res_type=res_type, 
            res_name=res_name, 
            status="manual", 
            details=details_dict
        ))

    return findings

def check_3_6_nat_gateway(resources):
    """
    3.6 NAT 게이트웨이 연결 관리 점검
    """
    findings = []

    for res in resources:
        res_type = res.get('type')
        if res_type != 'aws_nat_gateway':
            continue

        res_name = res.get('name')
        res_address = res.get('address', 'Unknown Address')
        
        change = res.get('change', {})
        after = change.get('after') or {}
        after_unknown = change.get('after_unknown') or {}
        tags = after.get('tags') or {}
        if str(tags.get("SecurityException3_6", "")).strip().lower() in {"approved", "true", "pass"}:
            continue

        # Name 태그 추출
        tags = after.get('tags') or {}
        tag_name = tags.get('Name', '태그 미지정')

        # Subnet ID 추출 (NAT GW가 생성될 서브넷)
        subnet_id = after.get('subnet_id')
        if not subnet_id:
            if isinstance(after_unknown, dict) and after_unknown.get('subnet_id') is True:
                subnet_id = "(생성 후 결정)"
            else:
                subnet_id = "Unknown Subnet"

        # 연결 타입(public / private) 추출 (AWS 기본값은 public)
        connectivity_type = after.get('connectivity_type', 'public')

        # 상세 정보를 Key-Value 형태로 구조화
        details_dict = {
            "message": "NAT 게이트웨이 생성이 감지되었습니다. 아웃바운드 라우팅 리뷰가 필요합니다.",
            "code_address": res_address,
            "resource_tag_name": tag_name,
            "placed_subnet_id": subnet_id,
            "connectivity_type": connectivity_type,
            "guide": "DB, 개인정보 보관 시스템 등 외부 인터넷 통신이 전면 차단되어야 하는 프라이빗 서브넷이 이 NAT 게이트웨이와 라우팅으로 연결되지 않았는지 확인하세요."
        }

        findings.append(create_finding(
            check_code="3.6", 
            check_name="NAT 게이트웨이 연결 관리", 
            res_type=res_type, 
            res_name=res_name, 
            status="manual", 
            details=details_dict
        ))

    return findings

def check_3_7_s3_access(resources):
    """3.7 S3 버킷/객체 접근 관리 점검"""
    
    CHECK_CODE = "3.7"
    CHECK_ITEM = "S3 버킷/객체 접근 관리"
    
    def create_finding(status, reason, resource=""):
        res_type, res_name = split_resource_identifier(resource)
        return {
            "check_code": CHECK_CODE,
            "check_name": CHECK_ITEM,
            "resource_type": res_type,
            "resource_name": res_name,
            "status": status,
            "severity": "HIGH" if status == "vulnerable" else "INFO",
            "details": reason
        }

    findings = []

    def _normalize_bucket_ref(value):
        if not isinstance(value, str):
            return None

        match = re.search(r"aws_s3_bucket\.([A-Za-z0-9_\-]+)\.(?:id|bucket|arn)$", value)
        if match:
            return match.group(1)

        match = re.search(r"aws_s3_bucket\.([A-Za-z0-9_\-]+)$", value)
        if match:
            return match.group(1)

        return value

    def _bucket_aliases(res_name, after):
        aliases = []

        for candidate in [
            res_name,
            after.get("bucket"),
            after.get("id"),
            after.get("arn"),
            f"aws_s3_bucket.{res_name}",
            f"aws_s3_bucket.{res_name}.id",
            f"aws_s3_bucket.{res_name}.bucket",
            f"aws_s3_bucket.{res_name}.arn",
        ]:
            normalized = _normalize_bucket_ref(candidate)
            if normalized and normalized not in aliases:
                aliases.append(normalized)

        return aliases

    # ================================
    # 1. S3 Inventory 구성
    # ================================
    buckets = {}
    pab_map = {}
    acl_map = {}
    policy_map = {}

    for res in resources:
        res_type = res.get("type")
        res_name = res.get("name")
        after = res.get("change", {}).get("after", {}) or {}

        if res_type == "aws_s3_bucket":
            buckets[res_name] = {
                "resource": f"aws_s3_bucket.{res_name}",
                "data": after,
                "aliases": _bucket_aliases(res_name, after)
            }

        elif res_type == "aws_s3_bucket_public_access_block":
            bucket_keys = []
            for candidate in [res_name, after.get("bucket")]:
                normalized = _normalize_bucket_ref(candidate)
                if normalized and normalized not in bucket_keys:
                    bucket_keys.append(normalized)
            for bucket_key in bucket_keys:
                pab_map[bucket_key] = after

        elif res_type == "aws_s3_bucket_acl":
            bucket_keys = []
            for candidate in [res_name, after.get("bucket")]:
                normalized = _normalize_bucket_ref(candidate)
                if normalized and normalized not in bucket_keys:
                    bucket_keys.append(normalized)
            for bucket_key in bucket_keys:
                acl_map[bucket_key] = after

        elif res_type == "aws_s3_bucket_policy":
            bucket_keys = []
            for candidate in [res_name, after.get("bucket")]:
                normalized = _normalize_bucket_ref(candidate)
                if normalized and normalized not in bucket_keys:
                    bucket_keys.append(normalized)
            for bucket_key in bucket_keys:
                policy_map[bucket_key] = after

    # ================================
    # 2. 버킷 없음
    # ================================
    if not buckets:
        return [create_finding("manual", "S3 버킷 리소스를 찾지 못했습니다.")]

    # ================================
    # 3. 개별 버킷 점검
    # ================================
    for bucket_name, bucket_info in buckets.items():
        resource = bucket_info["resource"]
        aliases = bucket_info.get("aliases", [bucket_name])

        reasons = []
        vulnerable = False
        manual = False

        pab = next((pab_map.get(alias) for alias in aliases if alias in pab_map), None)
        acl = next((acl_map.get(alias) for alias in aliases if alias in acl_map), None)
        policy = next((policy_map.get(alias) for alias in aliases if alias in policy_map), None)

        # --------------------------------
        # 1) Public Access Block
        # --------------------------------
        if not pab:
            vulnerable = True
            reasons.append("Public Access Block 설정 없음")
        else:
            flags = [
                pab.get("block_public_acls"),
                pab.get("ignore_public_acls"),
                pab.get("block_public_policy"),
                pab.get("restrict_public_buckets")
            ]

            if any(v is False for v in flags):
                vulnerable = True
                reasons.append("Public Access Block 일부 false")
            elif any(v is None for v in flags):
                manual = True
                reasons.append("Public Access Block 값 확인 필요")

        # --------------------------------
        # 2) ACL 점검
        # --------------------------------
        if acl:
            acl_val = str(acl.get("acl", "")).lower()

            if acl_val in ["public-read", "public-read-write"]:
                vulnerable = True
                reasons.append(f"ACL 공개 설정 ({acl_val})")
            elif acl_val == "private":
                reasons.append("ACL private")
            else:
                manual = True
                reasons.append(f"ACL 확인 필요 ({acl_val})")
        else:
            manual = True
            reasons.append("ACL 리소스 없음")

        # --------------------------------
        # 3) Bucket Policy
        # --------------------------------
        if policy:
            policy_str = str(policy.get("policy", ""))

            if (
                '"Principal":"*"' in policy_str
                or '"Principal": "*"' in policy_str
            ):
                if '"Action":"s3:*"' in policy_str:
                    vulnerable = True
                    reasons.append("Policy: 전체 권한 공개")
                elif '"Action":"s3:GetObject"' in policy_str:
                    vulnerable = True
                    reasons.append("Policy: 공개 읽기 허용")
                else:
                    manual = True
                    reasons.append("Policy: Principal * 존재 (추가 확인 필요)")
            else:
                reasons.append("Policy 정상")
        else:
            reasons.append("Policy 없음")

        # --------------------------------
        # 최종 판정
        # --------------------------------
        if vulnerable:
            status = "vulnerable"
        elif manual:
            status = "manual"
        else:
            status = "safe"

        findings.append(
            create_finding(
                status,
                " / ".join(reasons),
                resource
            )
        )

    return findings

def check_3_8_rds_subnet_az(resources, plan_data):
    """
    3.8 RDS 서브넷 가용영역 관리 점검
    기준:
    - subnet_ids를 확인할 수 없으면 vulnerable
    - subnet 참조는 있으나 availability_zone 매핑이 안 되면 vulnerable
    - subnet 수 또는 AZ 수가 3 이상이면 vulnerable
    - 그 외 safe
    """
    findings = []
    subnet_az_map = _build_subnet_az_map(resources)

    for res in resources:
        if res.get("type") != "aws_db_subnet_group":
            continue

        res_name = res.get("name", "")
        res_type = res.get("type", "")
        subnet_refs = _get_db_subnet_refs(plan_data, res)

        azs = []
        for subnet_ref in subnet_refs:
            az = subnet_az_map.get(subnet_ref)
            if az:
                azs.append(az)

        unique_subnet_refs = sorted(set(subnet_refs))
        unique_azs = sorted(set(azs))

        subnet_count = len(unique_subnet_refs)
        az_count = len(unique_azs)

        if subnet_count == 0:
            findings.append(
                create_finding(
                    "3.8",
                    "RDS 서브넷 가용영역 관리",
                    res_type,
                    res_name,
                    "vulnerable",
                    "aws_db_subnet_group.subnet_ids 값을 확인할 수 없습니다."
                )
            )
            continue

        if az_count == 0:
            findings.append(
                create_finding(
                    "3.8",
                    "RDS 서브넷 가용영역 관리",
                    res_type,
                    res_name,
                    "vulnerable",
                    f"서브넷 참조는 확인됐지만 aws_subnet.availability_zone 값을 확인할 수 없습니다. subnet_refs={unique_subnet_refs}"
                )
            )
            continue

        if subnet_count >= 3 or az_count >= 3:
            findings.append(
                create_finding(
                    "3.8",
                    "RDS 서브넷 가용영역 관리",
                    res_type,
                    res_name,
                    "vulnerable",
                    f"RDS DB 서브넷 그룹에 과도한 가용영역이 포함되어 있습니다. subnet 수={subnet_count}, AZ 수={az_count}, subnet_refs={unique_subnet_refs}, AZ={unique_azs}"
                )
            )
        else:
            findings.append(
                create_finding(
                    "3.8",
                    "RDS 서브넷 가용영역 관리",
                    res_type,
                    res_name,
                    "safe",
                    f"RDS DB 서브넷 그룹의 가용영역 수가 과도하지 않습니다. subnet 수={subnet_count}, AZ 수={az_count}, subnet_refs={unique_subnet_refs}, AZ={unique_azs}"
                )
            )

    if not findings:
        findings.append(
            create_finding(
                "3.8",
                "RDS 서브넷 가용영역 관리",
                "aws_db_subnet_group",
                "",
                "safe",
                "aws_db_subnet_group 리소스를 찾지 못했습니다."
            )
        )

    return findings

def check_3_9_alb(resources, plan_data):
    """3.9 ALB 연결 관리 점검 (tfplan.json resource_changes + configuration 기반)"""

    CHECK_CODE = "3.9"
    CHECK_ITEM = "ELB(Elastic Load Balancing) 연결 관리"
    CHECK_SEVERITY = "medium"

    def _make_finding(status, reason, resource=""):
        res_type, res_name = split_resource_identifier(resource)
        return {
            "check_code": CHECK_CODE,
            "check_name": CHECK_ITEM,
            "resource_type": res_type,
            "resource_name": res_name,
            "status": status,
            "severity": "HIGH" if status == "vulnerable" else "INFO",
            "details": reason
        }

    def _normalize_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            v = value.strip().lower()
            if v == "true":
                return True
            if v == "false":
                return False
        return None

    def _extract_lb_ref(value):
        if not isinstance(value, str):
            return None

        match = re.search(r"aws_lb\.([A-Za-z0-9_\-]+)\.(?:arn|id)", value)
        if match:
            return match.group(1)

        match = re.search(r"aws_lb\.([A-Za-z0-9_\-]+)$", value)
        if match:
            return match.group(1)

        return None

    def _extract_refs(values):
        if not isinstance(values, list):
            return []
        refs = []
        for value in values:
            if isinstance(value, str) and value not in refs:
                refs.append(value)
        return refs

    def _get_config_resource(address):
        root_module = plan_data.get("configuration", {}).get("root_module", {})
        for resource in _collect_all_config_resources(root_module):
            if resource.get("address") == address:
                return resource
        return {}

    def _get_expression_references(config_resource, expression_name):
        expr = config_resource.get("expressions", {}).get(expression_name, {})
        refs = expr.get("references", [])
        return [ref for ref in refs if isinstance(ref, str)] if isinstance(refs, list) else []

    def _extract_subnet_refs_from_config(config_resource):
        refs = _get_expression_references(config_resource, "subnets")
        return list(dict.fromkeys(ref for ref in refs if ref.startswith("aws_subnet.")))

    def _extract_sg_refs_from_config(config_resource):
        refs = _get_expression_references(config_resource, "security_groups")
        return list(dict.fromkeys(ref for ref in refs if ref.startswith("aws_security_group.")))

    def _extract_listener_protocol(config_resource, after):
        protocol = str(after.get("protocol", "")).upper()
        if protocol:
            return protocol
        return str(
            config_resource.get("expressions", {})
            .get("protocol", {})
            .get("constant_value", "")
        ).upper()

    def _extract_listener_certificate(config_resource, after):
        certificate_arn = after.get("certificate_arn")
        if certificate_arn:
            return certificate_arn

        refs = _get_expression_references(config_resource, "certificate_arn")
        if refs:
            return refs[0]

        cert_expr = config_resource.get("expressions", {}).get("certificate_arn", {})
        if isinstance(cert_expr, dict):
            return cert_expr.get("constant_value")

        return None

    def _has_https_redirect(after, config_resource):
        default_action = after.get("default_action")
        action_blocks = []

        if isinstance(default_action, list):
            action_blocks = [x for x in default_action if isinstance(x, dict)]
        elif isinstance(default_action, dict):
            action_blocks = [default_action]

        for action in action_blocks:
            action_type = str(action.get("type", "")).lower()
            if action_type != "redirect":
                continue

            redirect = action.get("redirect")
            redirect_blocks = []
            if isinstance(redirect, list):
                redirect_blocks = [x for x in redirect if isinstance(x, dict)]
            elif isinstance(redirect, dict):
                redirect_blocks = [redirect]

            for rb in redirect_blocks:
                if str(rb.get("protocol", "")).upper() == "HTTPS":
                    return True

        config_actions = config_resource.get("expressions", {}).get("default_action", [])
        if not isinstance(config_actions, list):
            return False

        for action in config_actions:
            if not isinstance(action, dict):
                continue

            action_type = action.get("type", {}).get("constant_value")
            if str(action_type).lower() != "redirect":
                continue

            redirect = action.get("redirect")
            redirect_blocks = []
            if isinstance(redirect, list):
                redirect_blocks = [x for x in redirect if isinstance(x, dict)]
            elif isinstance(redirect, dict):
                redirect_blocks = [redirect]

            for rb in redirect_blocks:
                protocol = str(rb.get("protocol", {}).get("constant_value", "")).upper()
                if protocol == "HTTPS":
                    return True

        return False

    findings = []

    albs = {}
    listeners = []
    waf_assoc_lb_refs = set()

    for res in resources:
        res_type = res.get("type")
        res_name = res.get("name")
        address = res.get("address", "")
        after = res.get("change", {}).get("after", {}) or {}

        if res_type == "aws_lb":
            lb_type = after.get("load_balancer_type", "application")
            if lb_type == "application":
                albs[res_name] = {
                    "resource": f"aws_lb.{res_name}",
                    "after": after,
                    "config_resource": _get_config_resource(address)
                }

        elif res_type == "aws_lb_listener":
            config_resource = _get_config_resource(address)
            lb_arn = after.get("load_balancer_arn")
            lb_ref = _extract_lb_ref(lb_arn) if isinstance(lb_arn, str) else None

            if not lb_ref:
                for ref in _get_expression_references(config_resource, "load_balancer_arn"):
                    lb_ref = _extract_lb_ref(ref)
                    if lb_ref:
                        break

            listeners.append({
                "resource": f"aws_lb_listener.{res_name}",
                "after": after,
                "lb_ref": lb_ref,
                "config_resource": config_resource
            })

        elif res_type in ["aws_wafv2_web_acl_association", "aws_wafregional_web_acl_association"]:
            resource_arn = after.get("resource_arn")
            lb_ref = _extract_lb_ref(resource_arn) if isinstance(resource_arn, str) else None
            if lb_ref:
                waf_assoc_lb_refs.add(lb_ref)

    if not albs:
        return [
            _make_finding(
                "safe",
                "tfplan.json에서 ALB(aws_lb, load_balancer_type=application) 리소스를 찾지 못했습니다."
            )
        ]

    for alb_name, alb_info in albs.items():
        after = alb_info["after"]
        config_resource = alb_info.get("config_resource", {})
        resource = alb_info["resource"]

        reasons = []
        vulnerable = False
        manual = False

        subnets = _extract_refs(after.get("subnets"))
        if not subnets:
            subnets = _extract_subnet_refs_from_config(config_resource)

        if len(subnets) >= 2:
            reasons.append(f"ALB가 {len(subnets)}개 서브넷에 연결되어 있습니다.")
        elif len(subnets) == 1:
            vulnerable = True
            reasons.append("ALB가 1개 서브넷에만 연결되어 있습니다.")
        else:
            vulnerable = True
            reasons.append("ALB의 subnet 연결을 확인할 수 없습니다.")

        security_groups = after.get("security_groups")
        if not (isinstance(security_groups, list) and len(security_groups) > 0):
            security_groups = _extract_sg_refs_from_config(config_resource)

        if isinstance(security_groups, list) and len(security_groups) > 0:
            reasons.append("보안 그룹이 연결되어 있습니다.")
        else:
            vulnerable = True
            reasons.append("보안 그룹 연결이 확인되지 않았습니다.")

        drop_invalid = _normalize_bool(after.get("drop_invalid_header_fields"))
        if drop_invalid is True:
            reasons.append("drop_invalid_header_fields가 활성화되어 있습니다.")
        elif drop_invalid is False:
            vulnerable = True
            reasons.append("drop_invalid_header_fields가 비활성화되어 있습니다.")
        else:
            manual = True
            reasons.append("drop_invalid_header_fields 값을 정적으로 확인할 수 없습니다.")

        deletion_protection = _normalize_bool(after.get("enable_deletion_protection"))
        if deletion_protection is True:
            reasons.append("삭제 방지 기능이 활성화되어 있습니다.")
        elif deletion_protection is False:
            vulnerable = True
            reasons.append("삭제 방지 기능이 비활성화되어 있습니다.")
        else:
            manual = True
            reasons.append("삭제 방지 기능 값을 정적으로 확인할 수 없습니다.")

        access_logs = after.get("access_logs")
        access_logs_enabled = None

        if isinstance(access_logs, list) and access_logs:
            first_log = access_logs[0]
            if isinstance(first_log, dict):
                access_logs_enabled = _normalize_bool(first_log.get("enabled"))
        elif isinstance(access_logs, dict):
            access_logs_enabled = _normalize_bool(access_logs.get("enabled"))

        if access_logs_enabled is True:
            reasons.append("액세스 로그가 활성화되어 있습니다.")
        elif access_logs_enabled is False:
            vulnerable = True
            reasons.append("액세스 로그가 비활성화되어 있습니다.")
        else:
            manual = True
            reasons.append("액세스 로그 설정을 확인할 수 없습니다.")

        if alb_name in waf_assoc_lb_refs:
            reasons.append("WAF 연결이 확인됩니다.")
        else:
            manual = True
            reasons.append("WAF 연결이 확인되지 않았습니다.")

        related_listeners = [x for x in listeners if x["lb_ref"] == alb_name]
        has_https_listener = False
        has_http_to_https_redirect = False

        for listener in related_listeners:
            lafter = listener["after"]
            listener_config = listener.get("config_resource", {})
            protocol = _extract_listener_protocol(listener_config, lafter)

            if protocol == "HTTPS":
                certificate_arn = _extract_listener_certificate(listener_config, lafter)
                if certificate_arn:
                    has_https_listener = True

            if protocol == "HTTP" and _has_https_redirect(lafter, listener_config):
                has_http_to_https_redirect = True

        if has_https_listener:
            reasons.append("HTTPS 리스너와 인증서 설정이 확인됩니다.")
        else:
            vulnerable = True
            reasons.append("HTTPS 리스너 또는 인증서 설정이 확인되지 않았습니다.")

        if has_http_to_https_redirect:
            reasons.append("HTTP → HTTPS 리다이렉트가 확인됩니다.")
        else:
            manual = True
            reasons.append("HTTP → HTTPS 리다이렉트가 확인되지 않았습니다.")

        if vulnerable:
            status = "vulnerable"
        elif manual:
            status = "manual"
        else:
            status = "safe"

        findings.append(
            _make_finding(
                status=status,
                reason=" / ".join(reasons),
                resource=resource
            )
        )

    return findings

def check_4_1_ebs(resources):
    """4.1 EBS 암호화 설정 점검 (tfplan.json resource_changes 기반)"""

    CHECK_CODE = "4.1"
    CHECK_ITEM = "EBS 암호화 설정"
    CHECK_SEVERITY = "medium"

    def _make_finding(status, reason, resource=""):
        res_type, res_name = split_resource_identifier(resource)
        return {
            "check_code": CHECK_CODE,
            "check_name": CHECK_ITEM,
            "resource_type": res_type,
            "resource_name": res_name,
            "status": status,
            "severity": "HIGH" if status == "vulnerable" else "INFO",
            "details": reason
        }

    def _normalize_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            v = value.strip().lower()
            if v == "true":
                return True
            if v == "false":
                return False
        return None

    def _to_block_list(value):
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    def _summarize_device(block):
        parts = []

        encrypted = _normalize_bool(block.get("encrypted"))
        kms_key_id = block.get("kms_key_id")
        volume_size = block.get("volume_size")
        volume_type = block.get("volume_type")
        delete_on_termination = _normalize_bool(block.get("delete_on_termination"))

        if encrypted is True:
            parts.append("encrypted=true")
        elif encrypted is False:
            parts.append("encrypted=false")
        else:
            parts.append("encrypted 미설정")
        if kms_key_id:
            parts.append(f"kms_key_id={kms_key_id}")
        if volume_size not in [None, ""]:
            parts.append(f"volume_size={volume_size}")
        if volume_type:
            parts.append(f"volume_type={volume_type}")

        if delete_on_termination is True:
            parts.append("delete_on_termination=true")
        elif delete_on_termination is False:
            parts.append("delete_on_termination=false")

        return ", ".join(parts)

    findings = []
    found_relevant_resource = False

    for res in resources:
        res_type = res.get("type")
        res_name = res.get("name")
        after = res.get("change", {}).get("after", {}) or {}

        # --------------------------------
        # aws_instance
        # --------------------------------
        if res_type == "aws_instance":
            found_relevant_resource = True
            resource = f"aws_instance.{res_name}"

            reasons = []
            vulnerable = False
            manual = False

            root_blocks = _to_block_list(after.get("root_block_device"))
            ebs_blocks = _to_block_list(after.get("ebs_block_device"))

            if not root_blocks and not ebs_blocks:
                manual = True
                reasons.append(
                    "root_block_device 또는 ebs_block_device가 없어 EBS 암호화 여부를 tfplan에서 명확히 확인할 수 없습니다."
                )

            for idx, root_block in enumerate(root_blocks, start=1):
                encrypted = _normalize_bool(root_block.get("encrypted"))
                summary = _summarize_device(root_block)

                if encrypted is True:
                    reasons.append(f"root_block_device #{idx}: {summary}")
                elif encrypted is False:
                    vulnerable = True
                    reasons.append(f"root_block_device #{idx}가 암호화되지 않았습니다. ({summary})")
                else:
                    manual = True
                    reasons.append(f"root_block_device #{idx}의 암호화 여부를 확인할 수 없습니다. ({summary})")

            for idx, ebs_block in enumerate(ebs_blocks, start=1):
                encrypted = _normalize_bool(ebs_block.get("encrypted"))
                summary = _summarize_device(ebs_block)

                if encrypted is True:
                    reasons.append(f"ebs_block_device #{idx}: {summary}")
                elif encrypted is False:
                    vulnerable = True
                    reasons.append(f"ebs_block_device #{idx}가 암호화되지 않았습니다. ({summary})")
                else:
                    manual = True
                    reasons.append(f"ebs_block_device #{idx}의 암호화 여부를 확인할 수 없습니다. ({summary})")

            if vulnerable:
                status = "vulnerable"
            elif manual:
                status = "manual"
            else:
                status = "safe"

            findings.append(
                _make_finding(
                    status=status,
                    reason=" / ".join(reasons),
                    resource=resource
                )
            )

        # --------------------------------
        # aws_ebs_volume
        # --------------------------------
        elif res_type == "aws_ebs_volume":
            found_relevant_resource = True
            resource = f"aws_ebs_volume.{res_name}"

            encrypted = _normalize_bool(after.get("encrypted"))
            summary = _summarize_device(after)

            if encrypted is True:
                status = "safe"
                reason = f"aws_ebs_volume이 암호화되어 있습니다. ({summary})"
            elif encrypted is False:
                status = "vulnerable"
                reason = f"aws_ebs_volume이 암호화되지 않았습니다. ({summary})"
            else:
                status = "manual"
                reason = f"aws_ebs_volume의 암호화 여부를 확인할 수 없습니다. ({summary})"

            findings.append(
                _make_finding(
                    status=status,
                    reason=reason,
                    resource=resource
                )
            )

        # --------------------------------
        # aws_volume_attachment
        # --------------------------------
        elif res_type == "aws_volume_attachment":
            found_relevant_resource = True
            resource = f"aws_volume_attachment.{res_name}"

            volume_id = after.get("volume_id")
            instance_id = after.get("instance_id")
            device_name = after.get("device_name")

            parts = ["aws_volume_attachment 리소스가 확인되었습니다."]
            if volume_id:
                parts.append(f"volume_id={volume_id}")
            if instance_id:
                parts.append(f"instance_id={instance_id}")
            if device_name:
                parts.append(f"device_name={device_name}")
            parts.append(
                "이 리소스는 연결 정보만 제공하므로 암호화 여부는 연결된 aws_ebs_volume 또는 aws_instance 설정으로 판단해야 합니다."
            )

            findings.append(
                _make_finding(
                    status="safe",
                    reason=" / ".join(parts),
                    resource=resource
                )
            )

    if not found_relevant_resource:
        findings.append(
            _make_finding(
                status="safe",
                reason="tfplan.json에서 aws_instance, aws_ebs_volume, aws_volume_attachment 리소스를 찾지 못했습니다."
            )
        )

    return findings

def check_4_2_rds_encrypted(resources):
    """4.2 RDS 암호화 설정 점검 (tfplan.json resource_changes 기반)"""

    CHECK_CODE = "4.2"
    CHECK_ITEM = "RDS 암호화 설정"
    CHECK_SEVERITY = "medium"

    def _make_finding(status, reason, resource=""):
        res_type, res_name = split_resource_identifier(resource)
        return {
            "check_code": CHECK_CODE,
            "check_name": CHECK_ITEM,
            "resource_type": res_type,
            "resource_name": res_name,
            "status": status,
            "severity": "HIGH" if status == "vulnerable" else "INFO",
            "details": reason
        }

    def _normalize_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            v = value.strip().lower()
            if v == "true":
                return True
            if v == "false":
                return False
        return None

    findings = []
    found_db_instance = False

    for res in resources:
        if res.get("type") != "aws_db_instance":
            continue

        found_db_instance = True
        res_name = res.get("name")
        resource = f"aws_db_instance.{res_name}"
        after = res.get("change", {}).get("after", {}) or {}

        reasons = []

        storage_encrypted = _normalize_bool(after.get("storage_encrypted"))
        kms_key_id = after.get("kms_key_id")

        if storage_encrypted is True:
            status = "safe"
            reasons.append("RDS 데이터베이스 암호화가 활성화되어 있습니다.")

            if kms_key_id:
                reasons.append(f"kms_key_id가 설정되어 있습니다: {kms_key_id}")
            else:
                reasons.append("kms_key_id는 명시되어 있지 않지만 storage_encrypted=true로 설정되어 있습니다.")

        elif storage_encrypted is False:
            status = "vulnerable"
            reasons.append("RDS 데이터베이스 암호화가 비활성화되어 있습니다.")

            if kms_key_id:
                reasons.append(f"kms_key_id가 설정되어 있으나 storage_encrypted=false입니다: {kms_key_id}")

        else:
            status = "manual"
            reasons.append("storage_encrypted 설정을 확인할 수 없습니다.")

            if kms_key_id:
                reasons.append(f"kms_key_id는 설정되어 있으나 암호화 활성화 여부(storage_encrypted)를 확인할 수 없습니다: {kms_key_id}")
            else:
                reasons.append("kms_key_id도 설정되어 있지 않습니다.")

        findings.append(
            _make_finding(
                status=status,
                reason=" / ".join(reasons),
                resource=resource
            )
        )

    if not found_db_instance:
        findings.append(
            _make_finding(
                status="safe",
                reason="tfplan.json에서 aws_db_instance 리소스를 찾지 못했습니다."
            )
        )

    return findings

def check_4_3_s3_encrypted(resources):
    """4.3 S3 암호화 설정 점검 (tfplan.json resource_changes 기반)"""

    CHECK_CODE = "4.3"
    CHECK_ITEM = "S3 암호화 설정"
    CHECK_SEVERITY = "medium"

    def _make_finding(status, reason, resource=""):
        res_type, res_name = split_resource_identifier(resource)
        return {
            "check_code": CHECK_CODE,
            "check_name": CHECK_ITEM,
            "resource_type": res_type,
            "resource_name": res_name,
            "status": status,
            "severity": "HIGH" if status == "vulnerable" else "INFO",
            "details": reason
        }

    def _normalize_bucket_ref(value):
        """
        예:
          aws_s3_bucket.main.id
          aws_s3_bucket.main.bucket
          aws_s3_bucket.main.arn
        -> main

        그 외 일반 문자열이면 그대로 반환
        """
        if not isinstance(value, str):
            return None

        match = re.search(r"aws_s3_bucket\.([A-Za-z0-9_\-]+)\.(?:id|bucket|arn)$", value)
        if match:
            return match.group(1)

        match = re.search(r"aws_s3_bucket\.([A-Za-z0-9_\-]+)$", value)
        if match:
            return match.group(1)

        return value

    def _bucket_aliases(res_name, after):
        aliases = []

        for candidate in [
            res_name,
            after.get("bucket"),
            after.get("id"),
            after.get("arn"),
            f"aws_s3_bucket.{res_name}",
            f"aws_s3_bucket.{res_name}.id",
            f"aws_s3_bucket.{res_name}.bucket",
            f"aws_s3_bucket.{res_name}.arn",
        ]:
            normalized = _normalize_bucket_ref(candidate)
            if normalized and normalized not in aliases:
                aliases.append(normalized)

        return aliases

    def _to_block_list(value):
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    findings = []

    buckets = {}
    encryption_map = {}

    # ==========================================
    # 1. inventory 구성
    # ==========================================
    for res in resources:
        res_type = res.get("type")
        res_name = res.get("name")
        after = res.get("change", {}).get("after", {}) or {}

        if res_type == "aws_s3_bucket":
            buckets[res_name] = {
                "resource": f"aws_s3_bucket.{res_name}",
                "after": after,
                "aliases": _bucket_aliases(res_name, after)
            }

        elif res_type == "aws_s3_bucket_server_side_encryption_configuration":
            bucket_keys = []

            for candidate in [res_name, after.get("bucket")]:
                normalized = _normalize_bucket_ref(candidate)
                if normalized and normalized not in bucket_keys:
                    bucket_keys.append(normalized)

            for bucket_key in bucket_keys:
                encryption_map[bucket_key] = after

    # ==========================================
    # 2. S3 버킷 없음
    # ==========================================
    if not buckets:
        return [
            _make_finding(
                status="safe",
                reason="tfplan.json에서 aws_s3_bucket 리소스를 찾지 못했습니다."
            )
        ]

    # ==========================================
    # 3. 개별 버킷 점검
    # ==========================================
    for bucket_name, bucket_info in buckets.items():
        resource = bucket_info["resource"]
        aliases = bucket_info.get("aliases", [bucket_name])
        reasons = []

        matched_after = next((encryption_map.get(alias) for alias in aliases if alias in encryption_map), None)

        if not matched_after:
            findings.append(
                _make_finding(
                    status="vulnerable",
                    reason="S3 버킷 기본 암호화 설정 리소스(aws_s3_bucket_server_side_encryption_configuration)를 확인할 수 없습니다.",
                    resource=resource
                )
            )
            continue

        found_safe = False
        rule_blocks = _to_block_list(matched_after.get("rule"))

        for rule_block in rule_blocks:
            sse_blocks = _to_block_list(rule_block.get("apply_server_side_encryption_by_default"))

            for sse_block in sse_blocks:
                sse_algorithm = sse_block.get("sse_algorithm")
                kms_master_key_id = sse_block.get("kms_master_key_id")

                if sse_algorithm == "AES256":
                    reasons.append("SSE-S3(AES256) 기본 암호화가 설정되어 있습니다.")
                    found_safe = True
                    break

                if sse_algorithm == "aws:kms":
                    if kms_master_key_id:
                        reasons.append(f"SSE-KMS 기본 암호화가 설정되어 있습니다: {kms_master_key_id}")
                    else:
                        reasons.append("SSE-KMS 기본 암호화가 설정되어 있습니다.")
                    found_safe = True
                    break

                if sse_algorithm:
                    reasons.append(f"지원 대상이 아닌 sse_algorithm 값입니다: {sse_algorithm}")

            if found_safe:
                break

        if found_safe:
            findings.append(
                _make_finding(
                    status="safe",
                    reason=" / ".join(reasons),
                    resource=resource
                )
            )
        else:
            if not reasons:
                reasons.append("기본 암호화 rule 또는 apply_server_side_encryption_by_default 설정을 확인할 수 없습니다.")

            findings.append(
                _make_finding(
                    status="vulnerable",
                    reason=" / ".join(reasons),
                    resource=resource
                )
            )

    return findings

# ==========================================
# 5. 통합 Main 함수
# ==========================================
def main():
    current_dir = BASE_DIR
    plan_path = os.path.join(TF_DIR, "tfplan.json")

    plan_data = load_plan(plan_path)
    if plan_data is None:
        return

    resources = get_valid_resources(plan_data)
    if not resources:
        print("Error: 유효한 리소스가 없습니다.")
        return

    all_results = []

    # 필요한 점검 함수들 추가
    all_results.extend(check_3_1_sg(resources))
    all_results.extend(check_3_2_sg(resources))
    all_results.extend(check_3_4_route_table(resources))
    all_results.extend(check_3_5_internet_gateway(resources))
    all_results.extend(check_3_6_nat_gateway(resources))
    all_results.extend(check_3_7_s3_access(resources))
    all_results.extend(check_3_8_rds_subnet_az(resources, plan_data))   
    all_results.extend(check_3_9_alb(resources, plan_data))
    all_results.extend(check_4_1_ebs(resources))
    all_results.extend(check_4_2_rds_encrypted(resources))
    all_results.extend(check_4_3_s3_encrypted(resources))

    final_output = {
        "scan_id": "scan_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S"),
        "timestamp": datetime.datetime.now().isoformat(),
        "project_name": "aws-tf-project",
        "total_resources_scanned": len(resources),
        "results": all_results
    }

    print(json.dumps(final_output, ensure_ascii=False, indent=2))

    output_path = os.path.join(current_dir, "result.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_output, f, ensure_ascii=False, indent=2)

# Embedded from remediation.py
import json
import os
import re
import shutil
import datetime
import subprocess
from typing import Any, Dict, List, Optional, Tuple


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_TF_DIR = os.path.join(BASE_DIR, "source_tf")
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
FIXED_TF_DIR = os.path.join(BASE_DIR, f"fixed_tf_{timestamp}")
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


def parse_result_resource_name(result: Dict[str, Any], expected_type: Optional[str] = None) -> Optional[str]:
    resource = build_resource_identifier(result)
    match = re.match(r"^([A-Za-z0-9_]+)\.([A-Za-z0-9_\-]+)$", resource)
    if not match:
        return None

    resource_type, resource_name = match.groups()
    if expected_type and resource_type != expected_type:
        return None

    return resource_name


def find_first_matching_resource_name(tf_dir: str, resource_type: str, bucket_name: str) -> Optional[str]:
    tf_dir = Path(tf_dir)
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
    tf_dir = Path(tf_dir)
    bucket_name = parse_result_resource_name(result, "aws_s3_bucket")
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
    tf_dir = Path(tf_dir)
    resource_name = parse_result_resource_name(result, "aws_lb")
    if not resource_name:
        return False

    def _patch(block_text: str) -> str:
        updated = block_text
        updated = replace_or_insert_attribute(updated, "drop_invalid_header_fields", "true")
        updated = replace_or_insert_attribute(updated, "enable_deletion_protection", "true")
        return updated

    return patch_resource_in_project(tf_dir, "aws_lb", resource_name, _patch)


def remediate_4_1_ebs(tf_dir: str, result: Dict[str, Any]) -> bool:
    tf_dir = Path(tf_dir)
    resource_name = parse_result_resource_name(result, "aws_instance")
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
    tf_dir = Path(tf_dir)
    resource_name = parse_result_resource_name(result, "aws_db_instance")
    if not resource_name:
        return False

    def _patch(block_text: str) -> str:
        updated = replace_or_insert_attribute(block_text, "storage_encrypted", "true")
        if "kms_key_id" not in updated:
            return updated
        return updated

    return patch_resource_in_project(tf_dir, "aws_db_instance", resource_name, _patch)


def remediate_4_3_s3(tf_dir: str, result: Dict[str, Any]) -> bool:
    tf_dir = Path(tf_dir)
    bucket_name = parse_result_resource_name(result, "aws_s3_bucket")
    if not bucket_name:
        return False

    sse_resource_name = find_first_matching_resource_name(
        tf_dir, "aws_s3_bucket_server_side_encryption_configuration", bucket_name
    ) or bucket_name

    def _patch_sse(block_text: str) -> str:
        updated = block_text
        updated = replace_or_insert_attribute(updated, "bucket", f"aws_s3_bucket.{bucket_name}.id")

        if 'sse_algorithm = "AES256"' in updated or 'sse_algorithm = "aws:kms"' in updated:
            return updated

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

    if find_first_matching_resource_name(
        tf_dir,
        "aws_s3_bucket_server_side_encryption_configuration",
        bucket_name,
    ):
        return False

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

# Embedded core workflow from Final.py
import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple



BASE_DIR = Path(__file__).resolve().parent
SOURCE_TF_DIR = BASE_DIR / "source_tf"
RUN_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
WORKFLOW_TIMESTAMP = RUN_TIMESTAMP
RUN_DIR = BASE_DIR / f"diag_run_{RUN_TIMESTAMP}"
FIXED_TF_DIR = BASE_DIR / f"fixed_tf_{RUN_TIMESTAMP}"

SOURCE_CHECKOV_RESULT = RUN_DIR / "step1_checkov_source.json"
SOURCE_CUSTOM_RESULT = RUN_DIR / "step2_custom_source.json"
SOURCE_MERGED_RESULT = RUN_DIR / "step2_merged_source.json"
FIXED_CHECKOV_RESULT = RUN_DIR / "step4_checkov_fixed.json"
FIXED_CUSTOM_RESULT = RUN_DIR / "step4_custom_fixed.json"
FIXED_MERGED_RESULT = RUN_DIR / "step4_merged_fixed.json"
WORKFLOW_SUMMARY = RUN_DIR / "workflow_summary.json"

CUSTOM_CHECKS = [
    ("check_3_1_sg", False),
    ("check_3_2_sg", False),
    ("check_3_4_route_table", False),
    ("check_3_5_internet_gateway", False),
    ("check_3_6_nat_gateway", False),
    ("check_3_7_s3_access", False),
    ("check_3_8_rds_subnet_az", True),
    ("check_3_9_alb", True),
    ("check_4_1_ebs", False),
    ("check_4_2_rds_encrypted", False),
    ("check_4_3_s3_encrypted", False),
]


# =========================
# 怨듯넻 ?좏떥
# =========================
def load_json(filepath: Path) -> Dict[str, Any]:
    with filepath.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(filepath: Path, data: Any) -> None:
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with filepath.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def ensure_clean_directory(target_dir: Path) -> None:
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)


def copy_tf_project(src_dir: Path, dst_dir: Path) -> None:
    ensure_clean_directory(dst_dir)

    for item in src_dir.iterdir():
        dst = dst_dir / item.name
        if item.is_dir():
            shutil.copytree(item, dst)
        else:
            shutil.copy2(item, dst)


def list_tf_files(tf_dir: Path) -> List[Path]:
    return list(tf_dir.rglob("*.tf"))


def read_text(filepath: Path) -> str:
    return filepath.read_text(encoding="utf-8")


def write_text(filepath: Path, content: str) -> None:
    filepath.write_text(content, encoding="utf-8")


def run_command(cmd: List[str], cwd: Optional[Path] = None) -> Tuple[int, str, str]:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"


def run_terraform_fmt(tf_dir: Path) -> None:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    try:
        subprocess.run(
            ["terraform", "fmt", "-recursive"],
            cwd=str(tf_dir),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    except FileNotFoundError:
        print("[WARN] terraform not found. Skipping terraform fmt.")


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

    for idx in range(brace_start, len(text)):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                return start, idx + 1
    return None


def find_block_ranges(text: str, block_name: str) -> List[Tuple[int, int]]:
    pattern = re.compile(rf'(?m)^([ \t]*){re.escape(block_name)}\s*\{{')
    ranges: List[Tuple[int, int]] = []

    for match in pattern.finditer(text):
        brace_start = match.end() - 1
        depth = 0
        for idx in range(brace_start, len(text)):
            if text[idx] == "{":
                depth += 1
            elif text[idx] == "}":
                depth -= 1
                if depth == 0:
                    ranges.append((match.start(), idx + 1))
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


def patch_child_block_attributes(
    block_text: str,
    child_block_name: str,
    attributes: Dict[str, str]
) -> Tuple[str, bool]:
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
            newer_child = replace_or_insert_attribute(new_child_block, key, value_expr, indent=attr_indent)
            if newer_child != new_child_block:
                changed = True
                new_child_block = newer_child

        updated_text = updated_text[:start] + new_child_block + updated_text[end:]

    return updated_text, changed


def patch_resource_in_file(filepath: Path, resource_type: str, resource_name: str, patch_fn) -> bool:
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


def patch_resource_in_project(tf_dir: Path, resource_type: str, resource_name: str, patch_fn) -> bool:
    for tf_file in list_tf_files(tf_dir):
        if patch_resource_in_file(tf_file, resource_type, resource_name, patch_fn):
            print(f"[PATCHED] {resource_type}.{resource_name} in {tf_file.name}")
            return True
    return False


def delete_resource_in_file(filepath: Path, resource_type: str, resource_name: str) -> bool:
    text = read_text(filepath)
    block_range = find_resource_block(text, resource_type, resource_name)
    if not block_range:
        return False

    start, end = block_range
    new_text = text[:start].rstrip() + "\n\n" + text[end:].lstrip()
    write_text(filepath, new_text.rstrip() + "\n")
    return True


def delete_resource_in_project(tf_dir: Path, resource_type: str, resource_name: str) -> bool:
    changed = False
    for tf_file in list_tf_files(tf_dir):
        if delete_resource_in_file(tf_file, resource_type, resource_name):
            print(f"[DELETED] {resource_type}.{resource_name} from {tf_file.name}")
            changed = True
    return changed


def append_resource_to_project(tf_dir: Path, filename: str, resource_block: str) -> None:
    target = tf_dir / filename
    if not target.exists():
        write_text(target, "")
    current = read_text(target)
    new_text = current.rstrip() + "\n\n" + resource_block.rstrip() + "\n"
    write_text(target, new_text)


def project_has_resource(tf_dir: Path, resource_type: str, resource_name: str) -> bool:
    for tf_file in list_tf_files(tf_dir):
        text = read_text(tf_file)
        if find_resource_block(text, resource_type, resource_name):
            return True
    return False


def append_resource_if_missing(
    tf_dir: Path,
    filename: str,
    resource_type: str,
    resource_name: str,
    resource_block: str,
) -> bool:
    if project_has_resource(tf_dir, resource_type, resource_name):
        return False
    append_resource_to_project(tf_dir, filename, resource_block)
    return True


def parse_resource_identifier(resource: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"^([A-Za-z0-9_]+)\.([A-Za-z0-9_\-]+)$", resource.strip())
    if not m:
        return None
    return m.group(1), m.group(2)


def deduplicate_failed_checks(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    failed = report.get("results", {}).get("failed_checks", [])
    seen = set()
    unique = []

    for item in failed:
        key = (item.get("check_id"), item.get("resource"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    return unique


def parse_checkov_output(output_text: str) -> Dict[str, Any]:
    output_text = (output_text or "").strip()
    if not output_text:
        raise ValueError("Checkov output is empty.")

    try:
        report = json.loads(output_text)
    except json.JSONDecodeError:
        report = None

    if report is None:
        for marker in ("{", "["):
            marker_index = output_text.find(marker)
            if marker_index == -1:
                continue
            try:
                report = json.loads(output_text[marker_index:])
                break
            except json.JSONDecodeError:
                continue

    if report is None:
        raise ValueError("Could not parse Checkov JSON output.")

    if isinstance(report, list):
        if not report:
            raise ValueError("Checkov returned an empty report list.")
        return report[0]

    if not isinstance(report, dict):
        raise ValueError("Unexpected Checkov report format.")

    return report


def infer_checkov_severity(item: Dict[str, Any]) -> str:
    existing = str(item.get("severity") or "").strip()
    if existing:
        return existing

    check_id = str(item.get("check_id") or "").upper()
    check_name = str(item.get("check_name") or "").lower()
    resource = str(item.get("resource") or "").lower()
    resource_type = resource.split(".", 1)[0] if resource else ""

    high_keywords = (
        "security group",
        "internet gateway",
        "nat gateway",
        "route",
        "public access",
        "metadata service",
        "waf",
        "tls",
        "cipher",
        "secret",
    )
    medium_keywords = (
        "logging",
        "monitoring",
        "versioning",
        "encryption",
        "backup",
        "rotation",
        "minor upgrade",
        "lifecycle",
        "flow log",
    )

    if resource_type in {"aws_security_group", "aws_route_table", "aws_internet_gateway", "aws_nat_gateway"}:
        return "HIGH"

    if any(keyword in check_name for keyword in high_keywords):
        return "HIGH"

    if check_id.startswith(("CKV2_AWS_", "CKV_AWS_")) and any(keyword in check_name for keyword in medium_keywords):
        return "MEDIUM"

    if resource_type in {"aws_s3_bucket", "aws_db_instance", "aws_dynamodb_table", "aws_instance", "aws_lb", "aws_wafv2_web_acl"}:
        return "MEDIUM"

    return "LOW"


def enrich_checkov_report_with_severity(report: Dict[str, Any]) -> Dict[str, Any]:
    results = report.get("results")
    if not isinstance(results, dict):
        return report

    failed_checks = results.get("failed_checks")
    if not isinstance(failed_checks, list):
        return report

    for item in failed_checks:
        if not isinstance(item, dict):
            continue
        item["severity"] = infer_checkov_severity(item)

    return report


def run_terraform_plan(tf_dir: Path, plan_json_path: Path) -> Optional[Path]:
    if not tf_dir.exists():
        print(f"[ERROR] Terraform directory not found: {tf_dir}")
        return None

    code, out, err = run_command(["terraform", "init", "-input=false", "-backend=false"], cwd=tf_dir)
    if code != 0:
        print(f"[WARN] terraform init failed ({tf_dir.name}): {err.strip()}")

    code, out, err = run_command(["terraform", "plan", "-out=tfplan"], cwd=tf_dir)
    if code != 0:
        print(f"[WARN] terraform plan failed ({tf_dir.name}): {err.strip()}")
        return None

    code, out, err = run_command(["terraform", "show", "-json", "tfplan"], cwd=tf_dir)
    if code != 0:
        print(f"[WARN] terraform show failed ({tf_dir.name}): {err.strip()}")
        return None

    plan_json_path.write_text(out, encoding="utf-8")
    print(f"[INFO] Generated tfplan.json at {plan_json_path}")
    return plan_json_path


def run_checkov(tf_dir: Path, output_path: Optional[Path] = None) -> Dict[str, Any]:
    if not tf_dir.exists():
        raise FileNotFoundError(f"Terraform directory not found: {tf_dir}")

    print(f"[CHECKOV] Running on {tf_dir}")
    commands = [
        ["checkov", "-d", str(tf_dir), "-o", "json", "--quiet"],
        ["python", "-m", "checkov.main", "-d", str(tf_dir), "--framework", "terraform", "--output", "json", "--quiet"],
    ]

    last_error = ""
    for command in commands:
        code, out, err = run_command(command, cwd=BASE_DIR)
        if code == 0 or out.strip():
            try:
                report = enrich_checkov_report_with_severity(parse_checkov_output(out))
                if output_path is not None:
                    write_json(output_path, report)
                return report
            except Exception as exc:
                last_error = f"{exc} | stderr={err.strip()}"
                continue
        last_error = err.strip() or f"Command failed: {' '.join(command)}"

    if output_path and output_path.exists():
        print(f"[INFO] Using existing checkov result from {output_path}")
        return enrich_checkov_report_with_severity(load_json(output_path))

    if last_error:
        print(f"[WARN] Checkov execution failed: {last_error}")

    return {"check_type":"terraform","results":{"failed_checks":[]}}


def run_custom_diagnosis(plan_path: Path, output_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    if not plan_path.exists():
        print(f"[WARN] Plan file not found for custom diagnosis: {plan_path}")
        return []

    plan_data = load_plan(plan_path)
    if not plan_data:
        return []

    resources = get_valid_resources(plan_data)

    findings = []
    for check_name, needs_plan_data in CUSTOM_CHECKS:
        fn = globals().get(check_name)
        if fn is None:
            print(f"[WARN] custom check not found: {check_name}")
            continue
        try:
            if needs_plan_data:
                findings.extend(fn(resources, plan_data))
            else:
                findings.extend(fn(resources))
        except Exception as exc:
            print(f"[WARN] custom check {check_name} failed: {exc}")

    for finding in findings:
        finding.setdefault("source", "custom")

    report = {
        "scan_id": f"custom_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "timestamp": datetime.now().isoformat(),
        "plan_path": str(plan_path),
        "total_resources_scanned": len(resources),
        "results": findings,
    }
    if output_path is not None:
        write_json(output_path, report)

    print(f"[CUSTOM] Diagnosis produced {len(findings)} findings")
    return findings


def merge_findings(
    checkov_report: Dict[str, Any],
    custom_findings: List[Dict[str, Any]],
    output_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    merged = []
    seen = set()

    for item in deduplicate_failed_checks(checkov_report):
        key = (item.get("check_id"), item.get("resource"))
        if key in seen:
            continue
        seen.add(key)
        item_copy = dict(item)
        item_copy["source"] = "checkov"
        merged.append(item_copy)

    for item in custom_findings:
        check_id = item.get("check_code", "CUSTOM")
        resource = f"{item.get('resource_type', 'unknown')}.{item.get('resource_name', 'unknown')}"
        custom_status = str(item.get("status", "")).strip().lower()
        merged_result = "PASSED" if custom_status in {"safe", "passed", "fixed"} else "FAILED"
        key = (check_id, resource)
        if key in seen:
            continue
        seen.add(key)

        merged.append({
            "check_id": check_id,
            "resource": resource,
            "check_name": item.get("check_name", "Custom Check"),
            "check_result": {"result": merged_result},
            "source": "custom",
            "details": item.get("details"),
        })

    print(f"[MERGE] Total merged findings: {len(merged)}")
    if output_path is not None:
        write_json(output_path, {"merged_findings": merged})
    return merged


def remediate_findings(merged_findings: List[Dict[str, Any]], source_dir: Path, target_dir: Path) -> Tuple[int, int]:
    copy_tf_project(source_dir, target_dir)
    fixed_count, skipped_count = 0, 0

    for item in merged_findings:
        check_id = str(item.get("check_id", "")).strip()
        resource = str(item.get("resource", "")).strip()
        remediation_fn = REMEDIATION_RULES.get(check_id)

        if not remediation_fn:
            print(f"[SKIP] No remediation rule: {check_id} / {resource}")
            skipped_count += 1
            continue

        try:
            if check_id in LEGACY_CUSTOM_REMEDIATION_RULES:
                changed = remediation_fn(target_dir, item)
            else:
                parsed = parse_resource_identifier(resource)
                if not parsed:
                    print(f"[SKIP] Invalid resource identifier: {check_id} / {resource}")
                    skipped_count += 1
                    continue
                _, resource_name = parsed
                changed = remediation_fn(target_dir, resource_name)
            if changed:
                fixed_count += 1
            else:
                skipped_count += 1
                print(f"[SKIP] Remediation not applied: {check_id} / {resource}")
        except Exception as exc:
            skipped_count += 1
            print(f"[ERROR] Remediation error: {check_id} / {resource} / {exc}")

    run_terraform_fmt(target_dir)
    return fixed_count, skipped_count


# =========================
# 蹂댁“ ?먯깋
# =========================
def find_any_kms_key(tf_dir: Path) -> Optional[str]:
    pattern = re.compile(r'resource\s+"aws_kms_key"\s+"([^"]+)"\s*\{')
    for tf_file in list_tf_files(tf_dir):
        text = read_text(tf_file)
        m = pattern.search(text)
        if m:
            return m.group(1)
    return None


def find_first_resource_name(tf_dir: Path, resource_type: str) -> Optional[str]:
    pattern = re.compile(rf'resource\s+"{re.escape(resource_type)}"\s+"([^"]+)"\s*\{{')
    for tf_file in list_tf_files(tf_dir):
        text = read_text(tf_file)
        m = pattern.search(text)
        if m:
            return m.group(1)
    return None


# =========================
# Checkov蹂?議곗튂 ?⑥닔
# =========================
def remediate_ckv_aws_126(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(block_text, "monitoring", "true")
    return patch_resource_in_project(tf_dir, "aws_instance", resource_name, _patch)


def remediate_ckv_aws_79(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        updated, changed = patch_child_block_attributes(
            block_text,
            "metadata_options",
            {
                "http_tokens": '"required"',
                "http_endpoint": '"enabled"',
            },
        )
        if changed:
            return updated

        insertion = """  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }"""
        return insert_before_last_brace(block_text, insertion)

    return patch_resource_in_project(tf_dir, "aws_instance", resource_name, _patch)


def remediate_ckv_aws_135(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(block_text, "ebs_optimized", "true")
    return patch_resource_in_project(tf_dir, "aws_instance", resource_name, _patch)


def remediate_ckv_aws_7(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(block_text, "enable_key_rotation", "true")
    return patch_resource_in_project(tf_dir, "aws_kms_key", resource_name, _patch)


def remediate_ckv_aws_28(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        updated, changed = patch_child_block_attributes(
            block_text,
            "point_in_time_recovery",
            {"enabled": "true"},
        )
        if changed:
            return updated

        insertion = """  point_in_time_recovery {
    enabled = true
  }"""
        return insert_before_last_brace(block_text, insertion)

    return patch_resource_in_project(tf_dir, "aws_dynamodb_table", resource_name, _patch)


def remediate_ckv_aws_119(tf_dir: Path, resource_name: str) -> bool:
    kms_name = find_any_kms_key(tf_dir)
    kms_expr = f"aws_kms_key.{kms_name}.arn" if kms_name else "null"

    def _patch(block_text: str) -> str:
        updated, changed = patch_child_block_attributes(
            block_text,
            "server_side_encryption",
            {
                "enabled": "true",
                "kms_key_arn": kms_expr,
            },
        )
        if changed:
            return updated

        insertion = f"""  server_side_encryption {{
    enabled     = true
    kms_key_arn = {kms_expr}
  }}"""
        return insert_before_last_brace(block_text, insertion)

    return patch_resource_in_project(tf_dir, "aws_dynamodb_table", resource_name, _patch)


def remediate_ckv_aws_129(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(
            block_text,
            "enabled_cloudwatch_logs_exports",
            '["error", "general", "slowquery"]'
        )
    return patch_resource_in_project(tf_dir, "aws_db_instance", resource_name, _patch)


def remediate_ckv_aws_226(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(block_text, "auto_minor_version_upgrade", "true")
    return patch_resource_in_project(tf_dir, "aws_db_instance", resource_name, _patch)


def remediate_ckv_aws_161(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(block_text, "iam_database_authentication_enabled", "true")
    return patch_resource_in_project(tf_dir, "aws_db_instance", resource_name, _patch)


def remediate_ckv_aws_293(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(block_text, "deletion_protection", "true")
    return patch_resource_in_project(tf_dir, "aws_db_instance", resource_name, _patch)


def remediate_ckv_aws_118(tf_dir: Path, resource_name: str) -> bool:
    role_resource_name = f"{resource_name}_enhanced_monitoring"
    role_changed = False
    if not project_has_resource(tf_dir, "aws_iam_role", role_resource_name):
        block = f'''resource "aws_iam_role" "{role_resource_name}" {{
  name = "{resource_name}-enhanced-monitoring-role"

  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Principal = {{
          Service = "monitoring.rds.amazonaws.com"
        }}
        Action = "sts:AssumeRole"
      }}
    ]
  }})
}}

resource "aws_iam_role_policy_attachment" "{role_resource_name}" {{
  role       = aws_iam_role.{role_resource_name}.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}}'''
        append_resource_to_project(tf_dir, "rds_enhanced_monitoring_remediation.tf", block)
        role_changed = True

    def _patch(block_text: str) -> str:
        updated = replace_or_insert_attribute(block_text, "monitoring_interval", "60")
        return replace_or_insert_attribute(
            updated,
            "monitoring_role_arn",
            f"aws_iam_role.{role_resource_name}.arn",
        )

    db_changed = patch_resource_in_project(tf_dir, "aws_db_instance", resource_name, _patch)
    return role_changed or db_changed


def remediate_ckv2_aws_60(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(block_text, "copy_tags_to_snapshot", "true")
    return patch_resource_in_project(tf_dir, "aws_db_instance", resource_name, _patch)


def remediate_ckv_aws_157(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(block_text, "multi_az", "true")
    return patch_resource_in_project(tf_dir, "aws_db_instance", resource_name, _patch)


def remediate_ckv_aws_103_or_ckv2_aws_74(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(
            block_text,
            "ssl_policy",
            '"ELBSecurityPolicy-TLS13-1-2-2021-06"'
        )
    return patch_resource_in_project(tf_dir, "aws_lb_listener", resource_name, _patch)


def remediate_ckv_aws_21(tf_dir: Path, resource_name: str) -> bool:
    block = f'''resource "aws_s3_bucket_versioning" "{resource_name}" {{
  bucket = aws_s3_bucket.{resource_name}.id

  versioning_configuration {{
    status = "Enabled"
  }}
}}'''
    if append_resource_if_missing(
        tf_dir,
        "s3_checkov_remediation.tf",
        "aws_s3_bucket_versioning",
        resource_name,
        block,
    ):
        print(f"[ADDED] Versioning for aws_s3_bucket.{resource_name}")
        return True
    return False


def remediate_ckv2_aws_61(tf_dir: Path, resource_name: str) -> bool:
    if resource_name.endswith("_replica"):
        primary_name = resource_name[: -len("_replica")]
        changed = False
        for resource_type in [
            "aws_s3_bucket_replication_configuration",
            "aws_s3_bucket_notification",
            "aws_s3_bucket_logging",
            "aws_s3_bucket_lifecycle_configuration",
            "aws_s3_bucket_server_side_encryption_configuration",
            "aws_s3_bucket_versioning",
            "aws_s3_bucket_public_access_block",
            "aws_s3_bucket",
        ]:
            target_name = primary_name if resource_type == "aws_s3_bucket_replication_configuration" else resource_name
            if delete_resource_in_project(tf_dir, resource_type, target_name):
                changed = True

        for resource_type, target_name in [
            ("aws_sns_topic_policy", "s3_events_secondary"),
            ("aws_sns_topic", "s3_events_secondary"),
            ("aws_iam_role_policy", "s3_replication"),
            ("aws_iam_role", "s3_replication"),
        ]:
            if delete_resource_in_project(tf_dir, resource_type, target_name):
                changed = True

        return changed

    block = f'''resource "aws_s3_bucket_lifecycle_configuration" "{resource_name}" {{
  bucket = aws_s3_bucket.{resource_name}.id

  rule {{
    id     = "default-lifecycle"
    status = "Enabled"

    expiration {{
      days = 365
    }}

    noncurrent_version_expiration {{
      noncurrent_days = 90
    }}
  }}
}}'''
    if append_resource_if_missing(
        tf_dir,
        "s3_checkov_remediation.tf",
        "aws_s3_bucket_lifecycle_configuration",
        resource_name,
        block,
    ):
        print(f"[ADDED] Lifecycle for aws_s3_bucket.{resource_name}")
        return True
    return False


def remediate_ckv_aws_145(tf_dir: Path, resource_name: str) -> bool:
    if resource_name.endswith("_replica"):
        return remediate_ckv2_aws_61(tf_dir, resource_name)

    kms_name = find_any_kms_key(tf_dir)
    if kms_name:
        sse_alg = '"aws:kms"'
        kms_line = f"\n      kms_master_key_id = aws_kms_key.{kms_name}.arn"
    else:
        sse_alg = '"AES256"'
        kms_line = ""

    block = f'''resource "aws_s3_bucket_server_side_encryption_configuration" "{resource_name}" {{
  bucket = aws_s3_bucket.{resource_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = {sse_alg}{kms_line}
    }}
  }}
}}'''

    def _patch(block_text: str) -> str:
        updated = replace_or_insert_attribute(
            block_text,
            "bucket",
            f"aws_s3_bucket.{resource_name}.id",
        )
        if 'sse_algorithm = "aws:kms"' in updated or 'sse_algorithm = "AES256"' in updated:
            if kms_name and "kms_master_key_id" not in updated:
                updated = updated.replace(
                    'sse_algorithm = "aws:kms"',
                    'sse_algorithm = "aws:kms"\n      kms_master_key_id = aws_kms_key.'
                    + kms_name
                    + '.arn',
                    1,
                )
            return updated

        return insert_before_last_brace(
            updated,
            f"""  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = {sse_alg}{kms_line}
    }}
  }}""",
        )

    sse_resource_name = find_first_matching_resource_name(
        str(tf_dir),
        "aws_s3_bucket_server_side_encryption_configuration",
        resource_name,
    ) or resource_name

    if patch_resource_in_project(
        tf_dir,
        "aws_s3_bucket_server_side_encryption_configuration",
        sse_resource_name,
        _patch,
    ):
        return True

    if append_resource_if_missing(
        tf_dir,
        "s3_checkov_remediation.tf",
        "aws_s3_bucket_server_side_encryption_configuration",
        sse_resource_name,
        block,
    ):
        print(f"[ADDED] SSE for aws_s3_bucket.{resource_name}")
        return True
    return False


def remediate_ckv_aws_149(tf_dir: Path, resource_name: str) -> bool:
    kms_name = find_any_kms_key(tf_dir)
    if not kms_name:
        kms_name = "secretsmanager"
        if not project_has_resource(tf_dir, "aws_kms_key", kms_name):
            block = f'''resource "aws_kms_key" "{kms_name}" {{
  description             = "KMS key for Secrets Manager"
  deletion_window_in_days = 7

  tags = {{
    Name = "secretsmanager-kms-key"
  }}
}}'''
            append_resource_to_project(tf_dir, "secrets_manager_kms_remediation.tf", block)

    def _patch(block_text: str) -> str:
        return replace_or_insert_attribute(block_text, "kms_key_id", f"aws_kms_key.{kms_name}.arn")

    return patch_resource_in_project(tf_dir, "aws_secretsmanager_secret", resource_name, _patch)


def remediate_ckv_aws_23(tf_dir: Path, resource_name: str) -> bool:
    def _patch(block_text: str) -> str:
        updated, _ = patch_child_block_attributes(
            block_text,
            "ingress",
            {"description": f'"Managed ingress for {resource_name}"'},
        )
        updated, _ = patch_child_block_attributes(
            updated,
            "egress",
            {"description": f'"Managed egress for {resource_name}"'},
        )
        return updated

    return patch_resource_in_project(tf_dir, "aws_security_group", resource_name, _patch)


def remediate_ckv2_aws_11(tf_dir: Path, resource_name: str) -> bool:
    log_group_block = f'''resource "aws_cloudwatch_log_group" "{resource_name}_flow_logs" {{
  name              = "/aws/vpc/flowlogs/{resource_name}"
  retention_in_days = 30
}}'''

    iam_role_block = f'''resource "aws_iam_role" "{resource_name}_flow_logs" {{
  name = "{resource_name}-flow-logs-role"

  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Principal = {{
          Service = "vpc-flow-logs.amazonaws.com"
        }}
        Action = "sts:AssumeRole"
      }}
    ]
  }})
}}

resource "aws_iam_role_policy" "{resource_name}_flow_logs" {{
  name = "{resource_name}-flow-logs-policy"
  role = aws_iam_role.{resource_name}_flow_logs.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }}
    ]
  }})
}}

resource "aws_flow_log" "{resource_name}" {{
  iam_role_arn         = aws_iam_role.{resource_name}_flow_logs.arn
  log_destination      = aws_cloudwatch_log_group.{resource_name}_flow_logs.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.{resource_name}.id
  log_destination_type = "cloud-watch-logs"
}}'''

    changed = False
    if append_resource_if_missing(
        tf_dir,
        "vpc_flow_log_remediation.tf",
        "aws_cloudwatch_log_group",
        f"{resource_name}_flow_logs",
        log_group_block,
    ):
        changed = True
    if append_resource_if_missing(
        tf_dir,
        "vpc_flow_log_remediation.tf",
        "aws_flow_log",
        resource_name,
        iam_role_block,
    ):
        changed = True
    if changed:
        print(f"[ADDED] Flow logs for aws_vpc.{resource_name}")
    return changed


def remediate_custom_with_legacy(tf_dir: Path, item: Dict[str, Any]) -> bool:
    check_id = str(item.get("check_id", "")).strip()
    remediation_fn = LEGACY_CUSTOM_REMEDIATION_RULES.get(check_id)
    if remediation_fn is None:
        return False
    return remediation_fn(str(tf_dir), item)


REMEDIATION_RULES = {
    "CKV_AWS_126": remediate_ckv_aws_126,
    "CKV_AWS_79": remediate_ckv_aws_79,
    "CKV_AWS_135": remediate_ckv_aws_135,
    "CKV_AWS_7": remediate_ckv_aws_7,
    "CKV_AWS_28": remediate_ckv_aws_28,
    "CKV_AWS_119": remediate_ckv_aws_119,
    "CKV_AWS_118": remediate_ckv_aws_118,
    "CKV_AWS_129": remediate_ckv_aws_129,
    "CKV_AWS_226": remediate_ckv_aws_226,
    "CKV_AWS_161": remediate_ckv_aws_161,
    "CKV_AWS_293": remediate_ckv_aws_293,
    "CKV_AWS_157": remediate_ckv_aws_157,
    "CKV2_AWS_60": remediate_ckv2_aws_60,
    "CKV_AWS_103": remediate_ckv_aws_103_or_ckv2_aws_74,
    "CKV2_AWS_74": remediate_ckv_aws_103_or_ckv2_aws_74,
    "CKV_AWS_21": remediate_ckv_aws_21,
    "CKV2_AWS_61": remediate_ckv2_aws_61,
    "CKV_AWS_145": remediate_ckv_aws_145,
    "CKV_AWS_149": remediate_ckv_aws_149,
    "CKV_AWS_23": remediate_ckv_aws_23,
    "CKV2_AWS_11": remediate_ckv2_aws_11,
    "3.7": remediate_custom_with_legacy,
    "3.9": remediate_custom_with_legacy,
    "4.1": remediate_custom_with_legacy,
    "4.2": remediate_custom_with_legacy,
    "4.3": remediate_custom_with_legacy,
}


LEGACY_CUSTOM_REMEDIATION_RULES = {
    "3.7": remediate_3_7_s3_access,
    "3.9": remediate_3_9_alb,
    "4.1": remediate_4_1_ebs,
    "4.2": remediate_4_2_rds,
    "4.3": remediate_4_3_s3,
}

# diag_Final.py remains the diagnosis entry point.
CHECKOV_RESULT = RUN_DIR / "step1_checkov_source.json"
CUSTOM_RESULT = RUN_DIR / "step2_custom_source.json"
MERGED_RESULT = RUN_DIR / "step2_merged_source.json"
SUMMARY_RESULT = RUN_DIR / "diagnosis_summary.json"


def main() -> None:
    if not SOURCE_TF_DIR.exists():
        print(f"[ERROR] source_tf not found: {SOURCE_TF_DIR}")
        return

    RUN_DIR.mkdir(parents=True, exist_ok=True)
    source_plan = SOURCE_TF_DIR / "tfplan.json"

    print("=== STEP 1: Checkov diagnosis ===")
    checkov_report = run_checkov(SOURCE_TF_DIR, CHECKOV_RESULT)

    print("\n=== STEP 2: Custom diagnosis ===")
    if not source_plan.exists():
        run_terraform_plan(SOURCE_TF_DIR, source_plan)
    custom_report = run_custom_diagnosis(source_plan, CUSTOM_RESULT)

    print("\n=== STEP 3: Merge diagnosis results ===")
    merged_report = merge_findings(checkov_report, custom_report, MERGED_RESULT)

    summary = {
        "run_timestamp": RUN_TIMESTAMP,
        "run_type": "diagnosis_only",
        "source_tf_dir": str(SOURCE_TF_DIR),
        "step1_checkov_failed": len(deduplicate_failed_checks(checkov_report)),
        "step2_custom_findings": len(custom_report),
        "step3_merged_findings": len(merged_report),
        "artifacts": {
            "step1_checkov": str(CHECKOV_RESULT),
            "step2_custom": str(CUSTOM_RESULT),
            "step3_merged": str(MERGED_RESULT),
        },
    }
    write_json(SUMMARY_RESULT, summary)

    print("\n=== Diagnosis complete ===")
    print(f"run_dir  = {RUN_DIR}")
    print(f"summary  = {SUMMARY_RESULT}")


if __name__ == "__main__":
    main()
