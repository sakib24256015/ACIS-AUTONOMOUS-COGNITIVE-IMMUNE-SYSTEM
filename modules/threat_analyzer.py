"""
modules/threat_analyzer.py
Heuristic-based real threat analysis.
"""

import datetime
import socket


class ThreatAnalyzer:

    KNOWN_MALICIOUS_IPS = {
        # Well-known botnet/C2 ranges (public threat intel)
        "192.168.0.0", "10.0.0.0",  # RFC1918 (just examples)
    }

    HIGH_RISK_PORTS = {
        4444: "Metasploit default",
        31337: "Back Orifice / Elite",
        12345: "NetBus Trojan",
        54321: "Reverse Shell common",
        1337: "Common backdoor",
        6667: "IRC C2 channel",
        6666: "IRC/Malware C2",
        9001: "Tor relay default",
        8888: "Common RAT",
    }

    CRITICAL_PROCS = {
        "mimikatz", "meterpreter", "empire", "beacon",
        "cobaltstrike", "metasploit", "msfconsole",
    }

    def full_scan(self, monitor) -> list:
        """Run a full system threat scan and return findings list."""
        findings = []
        ts = datetime.datetime.utcnow().isoformat()

        # ── 1. CPU spike detection ────────────────────────────────────────────
        metrics = monitor.get_system_metrics()
        if metrics["cpu_percent"] > 90:
            findings.append({
                "category": "ANOMALY",
                "severity": "HIGH",
                "message":  f"CPU spike detected: {metrics['cpu_percent']}% utilization",
                "source":   "system",
                "ts":       ts,
            })

        if metrics["memory_percent"] > 90:
            findings.append({
                "category": "ANOMALY",
                "severity": "MEDIUM",
                "message":  f"Memory pressure critical: {metrics['memory_percent']}% used",
                "source":   "system",
                "ts":       ts,
            })

        if metrics["disk_percent"] > 90:
            findings.append({
                "category": "ANOMALY",
                "severity": "MEDIUM",
                "message":  f"Disk near full: {metrics['disk_percent']}% used",
                "source":   "system",
                "ts":       ts,
            })

        # ── 2. Suspicious process scan ────────────────────────────────────────
        procs = monitor.get_all_processes()
        for p in procs:
            if p.get("suspicious"):
                findings.append({
                    "category": "MALWARE",
                    "severity": "CRITICAL",
                    "message":  f"Suspicious process detected: {p['name']} (PID {p['pid']})",
                    "source":   p["name"],
                    "ts":       ts,
                })
            if p["cpu"] > 80:
                findings.append({
                    "category": "ANOMALY",
                    "severity": "MEDIUM",
                    "message":  f"High CPU process: {p['name']} (PID {p['pid']}) at {p['cpu']}%",
                    "source":   p["name"],
                    "ts":       ts,
                })

        # ── 3. Network connection analysis ────────────────────────────────────
        conns = monitor.get_connections()
        seen_ports = set()
        for c in conns:
            if c.get("flagged"):
                findings.append({
                    "category": "NETWORK",
                    "severity": "HIGH",
                    "message":  f"Flagged connection: {c['local_addr']} → {c['remote_addr']} | {c.get('flag_reason','')}",
                    "source":   c.get("remote_addr", ""),
                    "ts":       ts,
                })

            # Check for high-risk port listeners
            if c["status"] == "LISTEN" and c["local_addr"]:
                try:
                    port = int(c["local_addr"].split(":")[-1])
                    if port in self.HIGH_RISK_PORTS and port not in seen_ports:
                        seen_ports.add(port)
                        findings.append({
                            "category": "NETWORK",
                            "severity": "CRITICAL",
                            "message":  f"Dangerous port {port} is OPEN ({self.HIGH_RISK_PORTS[port]})",
                            "source":   c["local_addr"],
                            "ts":       ts,
                        })
                except (ValueError, IndexError):
                    pass

        # ── 4. Interface anomaly ───────────────────────────────────────────────
        ifaces = monitor.get_interfaces()
        for iface in ifaces:
            if iface["errin"] > 1000 or iface["errout"] > 1000:
                findings.append({
                    "category": "NETWORK",
                    "severity": "MEDIUM",
                    "message":  f"High errors on {iface['name']}: in={iface['errin']} out={iface['errout']}",
                    "source":   iface["name"],
                    "ts":       ts,
                })

        # ── 5. Add INFO finding if all clear ──────────────────────────────────
        if not findings:
            findings.append({
                "category": "SCAN",
                "severity": "INFO",
                "message":  "Full system scan complete — no critical threats detected",
                "source":   "ACIS-Scanner",
                "ts":       ts,
            })

        return findings
