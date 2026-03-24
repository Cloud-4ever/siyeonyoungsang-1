import datetime
import json
import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TF_DIR = os.path.join(BASE_DIR, "fixed_tf")


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

    output_path = os.path.join(current_dir, "remedyresult.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_output, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()


