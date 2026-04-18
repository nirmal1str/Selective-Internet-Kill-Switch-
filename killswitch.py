import ipaddress
import logging
import os
import platform
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

try:
    from scapy.all import DNSRR, sniff
except Exception:
    DNSRR = None
    sniff = None

try:
    import psutil
except Exception:
    psutil = None


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

HOSTS_PATH = (
    r"C:\Windows\System32\drivers\etc\hosts"
    if platform.system() == "Windows"
    else "/etc/hosts"
)
HOSTS_MARKER = "aegis-block"
DNSMASQ_CONFIG_PATH = "/etc/dnsmasq.d/aegis-block.conf"
DOMAIN_ALIASES = {
    "instagram.com": [
        "cdninstagram.com",
        "fbcdn.net",
        "facebook.com",
        "graph.instagram.com",
        "i.instagram.com",
        "static.cdninstagram.com",
        "scontent.cdninstagram.com",
        "www.instagram.com",
    ],
    "youtube.com": [
        "googlevideo.com",
        "i.ytimg.com",
        "m.youtube.com",
        "youtu.be",
        "ytimg.com",
        "www.youtube.com",
    ],
}


class KillSwitchEngine:
    def __init__(self):
        self.rules = []
        self.logs = []
        self.rule_counter = 1
        self.sniff_thread = None
        self.monitor_thread = None
        self.running = False
        self.lock = threading.RLock()
        self.firewall = self._detect_firewall()
        self.dns_sinkhole = self._detect_dns_sinkhole()
        self.is_admin = self._is_admin()

    def add_log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = {"time": timestamp, "message": message}
        with self.lock:
            self.logs.insert(0, log_entry)
            if len(self.logs) > 100:
                self.logs.pop()
        logging.info(message)

    def add_rule(
        self,
        domain=None,
        rule_type="always",
        duration_minutes=None,
        start_time=None,
        end_time=None,
        target_type="domain",
        target=None,
    ):
        target_type = target_type if target_type in {"domain", "app"} else "domain"
        raw_target = target if target is not None else domain
        normalized_target = self._normalize_target(raw_target, target_type)
        if not normalized_target:
            if target_type == "app":
                return False, "Enter an app process name, for example firefox."
            return False, "Enter a valid domain, for example instagram.com."

        if target_type == "app" and psutil is None:
            return False, "Application blocking needs psutil. Install the project requirements."

        if rule_type not in {"always", "duration", "scheduled"}:
            return False, "Invalid rule type."

        if rule_type == "duration":
            try:
                duration_minutes = int(duration_minutes)
            except (TypeError, ValueError):
                return False, "Duration must be a number of minutes."
            if duration_minutes < 1:
                return False, "Duration must be at least 1 minute."

        if rule_type == "scheduled" and not self._valid_schedule(start_time, end_time):
            return False, "Schedule must include valid HH:MM start and end times."

        with self.lock:
            if any(r["target_type"] == target_type and r["target"] == normalized_target for r in self.rules):
                return False, "Rule for this target already exists."

            rule = {
                "id": self.rule_counter,
                "target_type": target_type,
                "target": normalized_target,
                "domain": normalized_target if target_type == "domain" else None,
                "app_name": normalized_target if target_type == "app" else None,
                "type": rule_type,
                "expires_at": time.time() + (duration_minutes * 60)
                if rule_type == "duration"
                else None,
                "schedule_start": start_time if rule_type == "scheduled" else None,
                "schedule_end": end_time if rule_type == "scheduled" else None,
                "active": False,
                "applied_ips": [],
                "applied_hosts": [],
                "blocked_pids": [],
                "last_error": None,
            }
            self.rules.append(rule)
            self.rule_counter += 1

        self.add_log(f"Added rule: block {target_type} {normalized_target} ({rule_type})")
        self._sync_rule(rule)

        if target_type == "app":
            if not self.is_admin:
                return True, "App rule saved. It can stop your user's processes; run with sudo to control all users."
            return True, "Application rule added successfully."

        if not self.is_admin:
            return True, "Rule saved, but OS blocking needs sudo/admin privileges."
        if self.dns_sinkhole == "dnsmasq":
            return True, "Rule added with DNS sinkhole, hosts, and firewall blocking."
        if not self.firewall and platform.system() != "Windows":
            return True, "Rule saved. Hosts blocking is active, but iptables/ip6tables were not found."
        return True, "Rule added with hosts and firewall blocking."

    def remove_rule(self, rule_id):
        with self.lock:
            rule = next((r for r in self.rules if r["id"] == int(rule_id)), None)
            if not rule:
                return False, "Rule not found."

        self.add_log(f"Removing rule for {rule['target']}")
        self._deactivate_rule(rule)

        with self.lock:
            self.rules = [r for r in self.rules if r["id"] != int(rule_id)]
        return True, f"Rule for {rule['target']} removed."

    def get_rules(self):
        with self.lock:
            return [dict(rule) for rule in self.rules]

    def get_logs(self):
        with self.lock:
            return list(self.logs)

    def get_status(self):
        return {
            "platform": platform.system(),
            "is_admin": self.is_admin,
            "hosts_path": HOSTS_PATH,
            "firewall": self.firewall or "none",
            "dns_sinkhole": self.dns_sinkhole or "none",
            "dnsmasq_config_path": DNSMASQ_CONFIG_PATH,
            "dns_resolver_local": self._dns_resolver_is_local(),
            "sniffer_available": sniff is not None and DNSRR is not None,
            "app_control_available": psutil is not None,
            "running": self.running,
        }

    def _normalize_target(self, value, target_type):
        if target_type == "app":
            return self._normalize_app_name(value)
        return self._normalize_domain(value)

    def _normalize_domain(self, value):
        value = (value or "").strip().lower()
        if not value:
            return ""
        if "://" in value:
            value = urlparse(value).netloc
        value = value.split("/")[0].split(":")[0].strip(".")
        if value.startswith("www."):
            value = value[4:]
        return value

    def _normalize_app_name(self, value):
        value = (value or "").strip()
        if not value:
            return ""
        value = os.path.basename(value)
        return value.strip().lower()

    def _valid_schedule(self, start_time, end_time):
        try:
            datetime.strptime(start_time, "%H:%M")
            datetime.strptime(end_time, "%H:%M")
            return True
        except (TypeError, ValueError):
            return False

    def _is_admin(self):
        if platform.system() == "Windows":
            try:
                import ctypes

                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _detect_firewall(self):
        if platform.system() == "Windows":
            return "windows-hosts"
        has_iptables = shutil.which("iptables") is not None
        has_ip6tables = shutil.which("ip6tables") is not None
        if has_iptables or has_ip6tables:
            return "iptables"
        return None

    def _detect_dns_sinkhole(self):
        if platform.system() == "Windows":
            return None
        if shutil.which("dnsmasq") is None:
            return None
        return "dnsmasq"

    def _dns_resolver_is_local(self):
        if platform.system() == "Windows":
            return False
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as resolv_file:
                for line in resolv_file:
                    line = line.strip()
                    if line.startswith("nameserver") and (
                        "127.0.0.1" in line
                        or "127.0.0.53" in line
                        or "::1" in line
                    ):
                        return True
        except OSError:
            return False
        return False

    def _domain_matches(self, check_domain, rule_domain):
        check_domain = check_domain.rstrip(".").lower()
        return any(
            check_domain == domain or check_domain.endswith(f".{domain}")
            for domain in self._expanded_domains(rule_domain)
        )

    def _expanded_domains(self, domain):
        domains = {domain, f"www.{domain}"}
        domains.update(DOMAIN_ALIASES.get(domain, []))
        if domain.startswith("www."):
            domains.add(domain[4:])
            domains.update(DOMAIN_ALIASES.get(domain[4:], []))
        return sorted(d for d in domains if d)

    def _is_rule_active_now(self, rule):
        if rule["type"] == "always":
            return True
        if rule["type"] == "duration":
            return time.time() < rule["expires_at"]
        if rule["type"] == "scheduled":
            now = datetime.now().strftime("%H:%M")
            start = rule["schedule_start"]
            end = rule["schedule_end"]
            if start <= end:
                return start <= now <= end
            return now >= start or now <= end
        return False

    def is_domain_currently_blocked(self, check_domain):
        with self.lock:
            rules = list(self.rules)
        for rule in rules:
            if (
                rule["target_type"] == "domain"
                and self._domain_matches(check_domain, rule["domain"])
                and self._is_rule_active_now(rule)
            ):
                return True, rule["domain"]
        return False, None

    def _resolve_domain(self, domain):
        addresses = set()
        candidates = self._expanded_domains(domain)
        for candidate in candidates:
            try:
                for result in socket.getaddrinfo(candidate, None):
                    ip = result[4][0]
                    try:
                        parsed = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if not parsed.is_loopback:
                        addresses.add(str(parsed))
            except socket.gaierror:
                continue
        return sorted(addresses)

    def _hosts_lines_for_domain(self, domain):
        marker = f"# {HOSTS_MARKER}:{domain}"
        lines = []
        for host in self._expanded_domains(domain):
            lines.append(f"0.0.0.0 {host} {marker}\n")
            lines.append(f"::1 {host} {marker}\n")
        return lines

    def _block_domain_hosts(self, domain):
        marker = f"{HOSTS_MARKER}:{domain}"
        try:
            with open(HOSTS_PATH, "r", encoding="utf-8") as hosts_file:
                lines = hosts_file.readlines()
            if any(marker in line for line in lines):
                return True
            with open(HOSTS_PATH, "a", encoding="utf-8") as hosts_file:
                hosts_file.write("\n")
                hosts_file.writelines(self._hosts_lines_for_domain(domain))
            self.add_log(f"Hosts block applied for {domain}")
            return True
        except PermissionError:
            self.add_log(f"Permission denied editing {HOSTS_PATH}. Run the app with sudo/admin.")
            return False
        except OSError as exc:
            self.add_log(f"Could not edit hosts file: {exc}")
            return False

    def _unblock_domain_hosts(self, domain):
        marker = f"{HOSTS_MARKER}:{domain}"
        try:
            with open(HOSTS_PATH, "r", encoding="utf-8") as hosts_file:
                lines = hosts_file.readlines()
            filtered = [line for line in lines if marker not in line]
            if filtered == lines:
                return True
            with open(HOSTS_PATH, "w", encoding="utf-8") as hosts_file:
                hosts_file.writelines(filtered)
            self.add_log(f"Hosts block removed for {domain}")
            return True
        except PermissionError:
            self.add_log(f"Permission denied editing {HOSTS_PATH}. Run the app with sudo/admin.")
            return False
        except OSError as exc:
            self.add_log(f"Could not edit hosts file: {exc}")
            return False

    def _active_sinkhole_domains(self):
        domains = set()
        with self.lock:
            rules = list(self.rules)
        for rule in rules:
            if rule["target_type"] != "domain" or not rule["active"] or not self._is_rule_active_now(rule):
                continue
            domains.update(self._expanded_domains(rule["domain"]))
        return sorted(domains)

    def _write_dnsmasq_config(self, domains):
        if self.dns_sinkhole != "dnsmasq":
            return False
        if not self.is_admin:
            return False

        try:
            os.makedirs(os.path.dirname(DNSMASQ_CONFIG_PATH), exist_ok=True)
            lines = [
                "# Generated by Aegis Selective Internet Kill Switch.\n",
                "# Delete rules from the Aegis UI instead of editing this file manually.\n",
            ]
            for domain in domains:
                lines.append(f"address=/{domain}/0.0.0.0\n")
                lines.append(f"address=/{domain}/::\n")
            with open(DNSMASQ_CONFIG_PATH, "w", encoding="utf-8") as config_file:
                config_file.writelines(lines)
            return True
        except PermissionError:
            self.add_log(f"Permission denied writing {DNSMASQ_CONFIG_PATH}. Run Aegis with sudo.")
            return False
        except OSError as exc:
            self.add_log(f"Could not write dnsmasq config: {exc}")
            return False

    def _reload_dnsmasq(self):
        if self.dns_sinkhole != "dnsmasq" or not self.is_admin:
            return False

        commands = [
            ["systemctl", "reload", "dnsmasq"],
            ["systemctl", "restart", "dnsmasq"],
            ["service", "dnsmasq", "reload"],
            ["service", "dnsmasq", "restart"],
        ]
        last_error = ""
        for cmd in commands:
            if shutil.which(cmd[0]) is None:
                continue
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                self.add_log("dnsmasq sinkhole rules reloaded.")
                return True
            last_error = (result.stderr or result.stdout or "").strip()

        if last_error:
            self.add_log(f"dnsmasq config written, but reload failed: {last_error}")
        else:
            self.add_log("dnsmasq config written, but no service manager was available to reload it.")
        return False

    def _sync_dns_sinkhole(self):
        if self.dns_sinkhole != "dnsmasq":
            return False
        domains = self._active_sinkhole_domains()
        if not self._write_dnsmasq_config(domains):
            return False
        reloaded = self._reload_dnsmasq()
        if domains:
            self.add_log(f"dnsmasq wildcard sinkhole covers {len(domains)} domain roots.")
        else:
            self.add_log("dnsmasq sinkhole cleared.")
        return reloaded

    def _firewall_command(self, action, target):
        try:
            version = ipaddress.ip_address(target).version
        except ValueError:
            return None
        binary = "ip6tables" if version == 6 else "iptables"
        if shutil.which(binary) is None:
            return None
        return [
            binary,
            action,
            "OUTPUT",
            "-d",
            target,
            "-m",
            "comment",
            "--comment",
            HOSTS_MARKER,
            "-j",
            "DROP",
        ]

    def _block_ip(self, target, domain):
        if not self.is_admin:
            return False
        check_cmd = self._firewall_command("-C", target)
        insert_cmd = self._firewall_command("-I", target)
        if not check_cmd or not insert_cmd:
            return False
        if subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return True
        result = subprocess.run(insert_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            self.add_log(f"Blocked traffic to {target} ({domain})")
            return True
        reason = (result.stderr or result.stdout or "unknown error").strip()
        self.add_log(f"Firewall refused block for {target}: {reason}")
        return False

    def _unblock_ip(self, target):
        if not self.is_admin:
            return
        delete_cmd = self._firewall_command("-D", target)
        if not delete_cmd:
            return
        while subprocess.run(delete_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            self.add_log(f"Removed firewall block for {target}")

    def _activate_rule(self, rule):
        if rule["target_type"] == "app":
            self._enforce_app_rule(rule)
            with self.lock:
                rule["active"] = True
                rule["last_error"] = None
            return

        domain = rule["domain"]
        resolved_ips = self._resolve_domain(domain)

        hosts_ok = self._block_domain_hosts(domain)
        with self.lock:
            rule["active"] = True
            rule["applied_hosts"] = self._expanded_domains(domain)
        sinkhole_ok = self._sync_dns_sinkhole()
        applied_ips = []
        for ip in resolved_ips:
            if self._block_ip(ip, domain):
                applied_ips.append(ip)

        with self.lock:
            rule["applied_ips"] = sorted(set(rule["applied_ips"]) | set(applied_ips))
            rule["last_error"] = None if hosts_ok or sinkhole_ok or applied_ips else "No OS-level block could be applied."

        if not resolved_ips:
            self.add_log(f"No DNS addresses resolved yet for {domain}; hosts block still covers direct visits.")

    def _deactivate_rule(self, rule):
        if rule["target_type"] == "app":
            with self.lock:
                rule["active"] = False
                rule["blocked_pids"] = []
            return

        domain = rule["domain"]
        self._unblock_domain_hosts(domain)
        with self.lock:
            rule["active"] = False
            applied_ips = list(rule["applied_ips"])
            rule["applied_hosts"] = []
        self._sync_dns_sinkhole()
        for ip in applied_ips:
            self._unblock_ip(ip)
        with self.lock:
            rule["applied_ips"] = []

    def _sync_rule(self, rule):
        should_be_active = self._is_rule_active_now(rule)
        if should_be_active and not rule["active"]:
            self._activate_rule(rule)
        elif should_be_active and rule["active"] and rule["target_type"] == "domain":
            self._refresh_domain_rule(rule)
        elif should_be_active and rule["active"] and rule["target_type"] == "app":
            self._enforce_app_rule(rule)
        elif not should_be_active and rule["active"]:
            self._deactivate_rule(rule)

    def _refresh_domain_rule(self, rule):
        domain = rule["domain"]
        new_ips = []
        with self.lock:
            applied_ips = set(rule["applied_ips"])
        for ip in self._resolve_domain(domain):
            if ip in applied_ips:
                continue
            if self._block_ip(ip, domain):
                new_ips.append(ip)
        if new_ips:
            with self.lock:
                rule["applied_ips"] = sorted(set(rule["applied_ips"]) | set(new_ips))

    def _process_matches_app(self, proc, app_name):
        try:
            name = (proc.info.get("name") or "").lower()
            exe = os.path.basename(proc.info.get("exe") or "").lower()
            cmdline = proc.info.get("cmdline") or []
            cmd = os.path.basename(cmdline[0]).lower() if cmdline else ""
            return app_name in {name, exe, cmd}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, IndexError):
            return False

    def _enforce_app_rule(self, rule):
        if psutil is None:
            with self.lock:
                rule["last_error"] = "psutil is unavailable."
            return

        app_name = rule["app_name"]
        killed_pids = []
        protected_pids = {os.getpid(), os.getppid()}
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                if proc.info["pid"] in protected_pids:
                    continue
                if not self._process_matches_app(proc, app_name):
                    continue
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except psutil.TimeoutExpired:
                    proc.kill()
                killed_pids.append(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
                with self.lock:
                    rule["last_error"] = f"Could not stop every {app_name} process: {exc}"

        if killed_pids:
            self.add_log(f"Stopped {app_name} process ids: {', '.join(str(pid) for pid in killed_pids)}")
            with self.lock:
                rule["blocked_pids"] = sorted(set(rule["blocked_pids"]) | set(killed_pids))

    def _process_packet(self, packet):
        if DNSRR is None or not packet.haslayer(DNSRR):
            return
        for i in range(packet[DNSRR].count):
            rrname_bytes = packet[DNSRR][i].rrname
            if not rrname_bytes:
                continue
            queried_domain = rrname_bytes.decode("utf-8", errors="ignore").rstrip(".")
            is_blocked, rule_domain = self.is_domain_currently_blocked(queried_domain)
            if not is_blocked or packet[DNSRR][i].type not in [1, 28]:
                continue
            ip = packet[DNSRR][i].rdata
            if not isinstance(ip, str):
                continue
            with self.lock:
                rule = next((r for r in self.rules if r["domain"] == rule_domain), None)
            if rule and ip not in rule["applied_ips"] and self._block_ip(ip, rule_domain):
                with self.lock:
                    rule["applied_ips"] = sorted(set(rule["applied_ips"]) | {ip})

    def _sniff_loop(self):
        if sniff is None or DNSRR is None:
            self.add_log("Scapy packet capture is unavailable; using resolver plus hosts blocking only.")
            return

        self.add_log("Started DNS packet capture engine.")
        try:
            sniff(filter="udp port 53", prn=self._process_packet, store=0, stop_filter=lambda _: not self.running)
        except PermissionError:
            self.add_log("Packet capture needs sudo/admin privileges.")
        except Exception as exc:
            self.add_log(f"Sniffing error: {exc}")

    def _monitor_loop(self):
        while self.running:
            with self.lock:
                rules = list(self.rules)
            for rule in rules:
                if rule["type"] == "duration" and time.time() >= rule["expires_at"]:
                    self.add_log(f"Rule expired for {rule['target']}")
                    self.remove_rule(rule["id"])
                else:
                    self._sync_rule(rule)
            time.sleep(5)

    def start(self):
        if self.running:
            return
        self.running = True
        self.add_log("Initializing Selective Internet Kill Switch Engine.")
        if not self.is_admin:
            self.add_log("OS-level blocking requires sudo/admin privileges.")
        if platform.system() != "Windows" and self.dns_sinkhole != "dnsmasq":
            self.add_log("dnsmasq not found; wildcard DNS sinkhole is disabled.")
        if platform.system() != "Windows" and not self.firewall:
            self.add_log("iptables/ip6tables not found; firewall IP blocking is disabled.")

        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        self.running = False
        self.add_log("Stopping engine and clearing rules.")
        with self.lock:
            rules = list(self.rules)
        for rule in rules:
            self.remove_rule(rule["id"])


engine = KillSwitchEngine()


if __name__ == "__main__":
    engine.start()
    engine.add_rule("instagram.com")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        engine.stop()
