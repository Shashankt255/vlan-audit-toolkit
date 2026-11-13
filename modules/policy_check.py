import ipaddress
from modules.base import BaseModule, Finding, HostResult, PortResult
from config import *


class PolicyCheckModule(BaseModule):
    MODULE_NAME = "Policy Compliance"
    MODULE_DESCRIPTION = "Compares actual reachability against expected segmentation policy"

    def _load_policy(self):
        return self.scan_config.get("policy", {})

    def _get_vlan_name(self, vlan_ref):
        src = self.scan_config.get("source_vlan", {})
        if vlan_ref.lower() in (src.get("name", "").lower(), str(src.get("vlan_id", ""))):
            return src.get("name", vlan_ref)

        for target in self.scan_config.get("targets", []):
            if vlan_ref.lower() in (target.get("name", "").lower(), str(target.get("vlan_id", ""))):
                return target.get("name", vlan_ref)

        return vlan_ref

    def _match_vlan(self, rule_vlan, actual_vlan_name):
        if not rule_vlan or not actual_vlan_name:
            return False
        return (rule_vlan.lower() == actual_vlan_name.lower() or
                rule_vlan.lower() in actual_vlan_name.lower() or
                actual_vlan_name.lower() in rule_vlan.lower() or
                rule_vlan == "*" or rule_vlan.lower() == "any")

    def _get_reachable_ports(self, target_vlan_name):
        alive_hosts = self.scan_config.get("alive_hosts", {})
        target_ranges = []
        for target in self.scan_config.get("targets", []):
            if self._match_vlan(target_vlan_name, target.get("name", "")):
                target_ranges = target.get("ranges", [])
                break

        reachable = {}
        for ip, host in alive_hosts.items():
            is_in_target = False
            if not target_ranges:
                is_in_target = True
            else:
                for r in target_ranges:
                    try:
                        if "/" in r:
                            if ipaddress.ip_address(ip) in ipaddress.ip_network(r, strict=False):
                                is_in_target = True
                                break
                        elif "-" in r:
                            start, end = r.split("-", 1)
                            start = start.strip()
                            end = end.strip()
                            if "." not in end:
                                base = ".".join(start.split(".")[:-1])
                                end = f"{base}.{end}"
                            if (ipaddress.ip_address(start) <=
                                    ipaddress.ip_address(ip) <=
                                    ipaddress.ip_address(end)):
                                is_in_target = True
                                break
                        elif ip == r:
                            is_in_target = True
                            break
                    except ValueError:
                        continue

            if not is_in_target:
                continue

            open_ports = set()
            if hasattr(host, "open_ports"):
                for pr in host.open_ports:
                    if hasattr(pr, "port"):
                        open_ports.add(pr.port)
                    elif isinstance(pr, int):
                        open_ports.add(pr)
            elif isinstance(host, dict):
                for p in host.get("open_ports", []):
                    if hasattr(p, "port"):
                        open_ports.add(p.port)
                    elif isinstance(p, int):
                        open_ports.add(p)

            if open_ports:
                reachable[ip] = open_ports

        return reachable

    def _evaluate_rules(self, policy):
        rules = policy.get("rules", [])
        src_vlan = self.scan_config.get("source_vlan", {})
        src_name = src_vlan.get("name", "Source VLAN")

        results = []
        for rule in rules:
            rule_src = rule.get("src_vlan", "")
            rule_dst = rule.get("dst_vlan", "")
            rule_ports = rule.get("ports", "any")
            rule_action = rule.get("action", "deny").lower()

            if not self._match_vlan(rule_src, src_name):
                results.append({
                    "rule": rule,
                    "status": "not_applicable",
                    "reason": f"Source VLAN '{rule_src}' does not match current source '{src_name}'",
                })
                continue

            reachable = self._get_reachable_ports(rule_dst)

            if isinstance(rule_ports, list):
                check_ports = set(rule_ports)
            elif rule_ports == "any" or rule_ports == "*":
                check_ports = None
            elif rule_ports == "any_other":
                other_allow_ports = set()
                for other_rule in rules:
                    if (self._match_vlan(other_rule.get("src_vlan", ""), src_name) and
                            self._match_vlan(other_rule.get("dst_vlan", ""), rule_dst) and
                            other_rule.get("action", "").lower() == "allow" and
                            isinstance(other_rule.get("ports"), list)):
                        other_allow_ports.update(other_rule["ports"])
                check_ports = None
                extra_ports_flag = other_allow_ports
            else:
                check_ports = None

            violations = []
            compliant_hosts = []

            for ip, ports in reachable.items():
                if check_ports is not None:
                    matched_ports = ports & check_ports
                elif rule_ports == "any_other":
                    matched_ports = ports - extra_ports_flag
                else:
                    matched_ports = ports

                if rule_action == "allow":
                    if check_ports and not matched_ports:
                        violations.append({
                            "ip": ip,
                            "expected_ports": sorted(check_ports),
                            "actual_open": sorted(ports),
                            "issue": "expected_ports_not_open",
                        })
                    else:
                        compliant_hosts.append(ip)
                elif rule_action == "deny":
                    if matched_ports:
                        violations.append({
                            "ip": ip,
                            "denied_ports_open": sorted(matched_ports),
                            "issue": "denied_traffic_allowed",
                        })
                    else:
                        compliant_hosts.append(ip)

            if not reachable and rule_action == "deny":
                status = "compliant"
            elif not reachable and rule_action == "allow":
                status = "no_hosts_reachable"
            elif violations:
                status = "violation"
            else:
                status = "compliant"

            results.append({
                "rule": rule,
                "status": status,
                "violations": violations,
                "compliant_hosts": compliant_hosts,
                "hosts_checked": len(reachable),
            })

        return results

    def _generate_compliance_matrix(self, eval_results):
        matrix = {}
        for result in eval_results:
            rule = result["rule"]
            src = rule.get("src_vlan", "?")
            dst = rule.get("dst_vlan", "?")
            action = rule.get("action", "?")
            key = f"{src} -> {dst}"

            if key not in matrix:
                matrix[key] = {"src_vlan": src, "dst_vlan": dst, "rules": []}

            matrix[key]["rules"].append({
                "action": action,
                "ports": rule.get("ports", "any"),
                "status": result["status"],
                "violations": len(result.get("violations", [])),
            })
        return matrix

    def _generate_recommended_policy(self):
        recommendations = []
        src_vlan = self.scan_config.get("source_vlan", {})
        src_name = src_vlan.get("name", "Source VLAN")
        alive_hosts = self.scan_config.get("alive_hosts", {})

        db_ports = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017}
        mgmt_ports = set(MANAGEMENT_PORTS)
        critical_svc_ports = {445, 135, 139, 88, 389, 636, 3268}

        for target in self.scan_config.get("targets", []):
            target_name = target.get("name", "Unknown VLAN")
            target_ranges = target.get("ranges", [])

            reachable_db = set()
            reachable_mgmt = set()
            reachable_critical = set()

            for ip, host in alive_hosts.items():
                open_ports = set()
                if hasattr(host, "open_ports"):
                    for pr in host.open_ports:
                        if hasattr(pr, "port"):
                            open_ports.add(pr.port)
                elif isinstance(host, dict):
                    for p in host.get("open_ports", []):
                        if hasattr(p, "port"):
                            open_ports.add(p.port)
                        elif isinstance(p, int):
                            open_ports.add(p)

                reachable_db.update(open_ports & db_ports)
                reachable_mgmt.update(open_ports & mgmt_ports)
                reachable_critical.update(open_ports & critical_svc_ports)

            if reachable_db:
                port_names = [CRITICAL_PORTS.get(p, (str(p), ""))[0] for p in sorted(reachable_db)]
                recommendations.append({
                    "src_vlan": src_name,
                    "dst_vlan": target_name,
                    "ports": sorted(reachable_db),
                    "action": "deny",
                    "reason": f"Database ports ({', '.join(port_names)}) should not be directly accessible from {src_name}",
                    "severity": SEVERITY_HIGH,
                })

            if reachable_mgmt:
                recommendations.append({
                    "src_vlan": src_name,
                    "dst_vlan": target_name,
                    "ports": sorted(reachable_mgmt),
                    "action": "deny",
                    "reason": f"Management ports should be restricted to a dedicated management VLAN",
                    "severity": SEVERITY_MEDIUM,
                })

            if reachable_critical:
                port_names = [CRITICAL_PORTS.get(p, (str(p), ""))[0] for p in sorted(reachable_critical)]
                recommendations.append({
                    "src_vlan": src_name,
                    "dst_vlan": target_name,
                    "ports": sorted(reachable_critical),
                    "action": "deny",
                    "reason": f"Critical services ({', '.join(port_names)}) should be segmented",
                    "severity": SEVERITY_MEDIUM,
                })

        if not recommendations:
            recommendations.append({
                "src_vlan": src_name,
                "dst_vlan": "*",
                "ports": "any_unnecessary",
                "action": "deny",
                "reason": "Apply default-deny policy and allow only required traffic",
                "severity": SEVERITY_INFO,
            })

        return recommendations

    def execute(self):
        src_vlan = self.scan_config.get("source_vlan", {})
        src_name = src_vlan.get("name", "Source VLAN")

        policy = self._load_policy()
        rules = policy.get("rules", [])

        # POL-001: Policy Load
        if rules:
            self.add_finding(
                test_id="POL-001",
                test_name="Segmentation Policy Loaded",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Segmentation policy loaded for compliance evaluation.",
                observation=f"Policy contains {len(rules)} rule(s). "
                            f"Allow rules: {sum(1 for r in rules if r.get('action', '').lower() == 'allow')}. "
                            f"Deny rules: {sum(1 for r in rules if r.get('action', '').lower() == 'deny')}.",
                details={"rule_count": len(rules), "rules": rules},
                source_vlan=src_name,
            )

            # POL-002: Evaluate Rules
            eval_results = self._evaluate_rules(policy)
            violations = [r for r in eval_results if r["status"] == "violation"]
            compliant = [r for r in eval_results if r["status"] == "compliant"]
            skipped = [r for r in eval_results if r["status"] == "not_applicable"]

            for result in violations:
                rule = result["rule"]
                rule_desc = (f"{rule.get('src_vlan', '?')} -> {rule.get('dst_vlan', '?')} "
                             f"[{rule.get('action', '?').upper()}] ports={rule.get('ports', 'any')}")

                violation_details = []
                for v in result.get("violations", []):
                    if v["issue"] == "denied_traffic_allowed":
                        ports = v.get("denied_ports_open", [])
                        port_names = [f"{p}/{CRITICAL_PORTS.get(p, (str(p), ''))[0]}" for p in ports]
                        violation_details.append(f"{v['ip']}: ports {', '.join(port_names)} open (should be denied)")
                    elif v["issue"] == "expected_ports_not_open":
                        violation_details.append(f"{v['ip']}: expected ports {v['expected_ports']} not all open")

                severity = SEVERITY_CRITICAL if rule.get("action", "").lower() == "deny" else SEVERITY_MEDIUM
                self.add_finding(
                    test_id="POL-002",
                    test_name=f"Policy Violation: {rule_desc}",
                    category=self.MODULE_NAME,
                    status=STATUS_FAIL,
                    severity=severity,
                    description=f"Segmentation policy rule violated: {rule_desc}.",
                    observation=f"{len(result['violations'])} host(s) violating this rule. "
                                f"Details: {'; '.join(violation_details[:10])}",
                    remediation=f"Configure ACLs/firewall rules to enforce: {rule_desc}. "
                                "Verify switch VLAN configuration and inter-VLAN routing ACLs.",
                    affected_objects=[v.get("ip", "?") for v in result.get("violations", [])],
                    details={"rule": rule, "violations": result["violations"]},
                    source_vlan=src_name,
                    target_vlan=rule.get("dst_vlan", ""),
                )

            # POL-003: Compliance Summary
            total = len(eval_results)
            applicable = total - len(skipped)
            compliant_count = len(compliant)
            violation_count = len(violations)
            compliance_pct = round((compliant_count / applicable * 100) if applicable > 0 else 0, 1)

            matrix = self._generate_compliance_matrix(eval_results)

            if violation_count > 0:
                status = STATUS_FAIL
                severity = SEVERITY_HIGH
            elif applicable == 0:
                status = STATUS_SKIP
                severity = SEVERITY_INFO
            else:
                status = STATUS_PASS
                severity = SEVERITY_INFO

            self.add_finding(
                test_id="POL-003",
                test_name="Policy Compliance Summary",
                category=self.MODULE_NAME,
                status=status,
                severity=severity,
                description="Overall segmentation policy compliance assessment.",
                observation=f"Compliance: {compliance_pct}% ({compliant_count}/{applicable} applicable rules). "
                            f"Violations: {violation_count}. "
                            f"Skipped (not applicable): {len(skipped)}.",
                remediation=f"Address {violation_count} policy violation(s) by configuring appropriate "
                            "ACLs and firewall rules." if violation_count > 0 else "",
                details={
                    "compliance_percentage": compliance_pct,
                    "total_rules": total,
                    "applicable_rules": applicable,
                    "compliant": compliant_count,
                    "violations": violation_count,
                    "skipped": len(skipped),
                    "matrix": matrix,
                },
                source_vlan=src_name,
            )

        else:
            # No policy provided — generate recommendations
            self.add_finding(
                test_id="POL-001",
                test_name="Segmentation Policy",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="No segmentation policy provided. Generating recommendations based on scan results.",
                observation="Policy-based compliance checking requires a 'policy' section in the scan config "
                            "with rules defining allowed and denied traffic between VLANs. "
                            "See sample-config.yaml for the policy format.",
                remediation="Define a segmentation policy in the YAML config file under the 'policy' key.",
                source_vlan=src_name,
            )

            recommendations = self._generate_recommended_policy()
            if recommendations:
                rec_text = []
                for rec in recommendations:
                    ports_str = (", ".join(str(p) for p in rec["ports"])
                                 if isinstance(rec["ports"], list) else str(rec["ports"]))
                    rec_text.append(
                        f"  {rec['action'].upper()}: {rec['src_vlan']} -> {rec['dst_vlan']} "
                        f"ports=[{ports_str}] — {rec['reason']}"
                    )

                self.add_finding(
                    test_id="POL-002",
                    test_name="Recommended Segmentation Policy",
                    category=self.MODULE_NAME,
                    status=STATUS_WARN,
                    severity=SEVERITY_MEDIUM,
                    description="Recommended segmentation rules based on observed reachability.",
                    observation=f"Based on scan results, {len(recommendations)} rule(s) recommended:\n"
                                + "\n".join(rec_text),
                    remediation="Implement the recommended rules as ACLs on inter-VLAN routing devices. "
                                "Add these rules to the scan config 'policy' section for automated compliance checking.",
                    details={"recommendations": recommendations},
                    source_vlan=src_name,
                )

            self.add_finding(
                test_id="POL-003",
                test_name="Policy Compliance Summary",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="Policy compliance evaluation skipped — no policy defined.",
                observation="Define a policy in the scan configuration to enable automated compliance checking.",
                source_vlan=src_name,
            )
