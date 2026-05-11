"""
modules/monitor.py
Real system monitoring using psutil.
"""

import socket
import platform
import datetime
import time
import os

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# Ports considered suspicious / high-risk
SUSPICIOUS_PORTS = {
    23, 135, 137, 138, 139, 445, 1433, 1434, 3389,
    4444, 5555, 6666, 7777, 8080, 8443, 9001, 9090,
    31337, 12345, 54321, 65000, 65535,
}

# Process names associated with known threats / pentest tools
SUSPICIOUS_PROCS = {
    "netcat", "nc", "ncat", "nmap", "masscan", "metasploit",
    "msfconsole", "msfvenom", "hydra", "john", "hashcat",
    "mimikatz", "cobalt", "beacon", "empire", "powershell",
    "cmd", "wscript", "cscript", "regsvr32", "mshta",
}

_last_net_io = None
_last_net_time = None


class SystemMonitor:

    # ── System Metrics ────────────────────────────────────────────────────────
    def get_system_metrics(self) -> dict:
        if not PSUTIL_OK:
            return self._fallback_metrics()

        cpu_pct   = psutil.cpu_percent(interval=0.3)
        cpu_count = psutil.cpu_count(logical=True)
        mem       = psutil.virtual_memory()
        disk      = psutil.disk_usage("/")
        boot_ts   = psutil.boot_time()
        boot_dt   = datetime.datetime.fromtimestamp(boot_ts)
        uptime    = time.time() - boot_ts
        net_io    = psutil.net_io_counters()

        # CPU per-core
        per_core = psutil.cpu_percent(percpu=True)

        return {
            "cpu_percent":     round(cpu_pct, 1),
            "cpu_count":       cpu_count,
            "cpu_per_core":    [round(c, 1) for c in per_core],
            "cpu_freq":        round(psutil.cpu_freq().current, 0) if psutil.cpu_freq() else 0,
            "memory_percent":  round(mem.percent, 1),
            "memory_total":    mem.total,
            "memory_used":     mem.used,
            "memory_available":mem.available,
            "disk_percent":    round(disk.percent, 1),
            "disk_total":      disk.total,
            "disk_used":       disk.used,
            "disk_free":       disk.free,
            "net_bytes_sent":  net_io.bytes_sent,
            "net_bytes_recv":  net_io.bytes_recv,
            "net_packets_sent":net_io.packets_sent,
            "net_packets_recv":net_io.packets_recv,
            "net_errin":       net_io.errin,
            "net_errout":      net_io.errout,
            "boot_time":       boot_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "uptime_seconds":  int(uptime),
        }

    def _fallback_metrics(self) -> dict:
        """Minimal data when psutil unavailable."""
        return {
            "cpu_percent": 0, "cpu_count": os.cpu_count() or 1,
            "cpu_per_core": [], "cpu_freq": 0,
            "memory_percent": 0, "memory_total": 0, "memory_used": 0, "memory_available": 0,
            "disk_percent": 0, "disk_total": 0, "disk_used": 0, "disk_free": 0,
            "net_bytes_sent": 0, "net_bytes_recv": 0,
            "net_packets_sent": 0, "net_packets_recv": 0,
            "net_errin": 0, "net_errout": 0,
            "boot_time": "N/A", "uptime_seconds": 0,
        }

    # ── Network Interfaces ────────────────────────────────────────────────────
    def get_interfaces(self) -> list:
        if not PSUTIL_OK:
            return []
        interfaces = []
        stats   = psutil.net_if_stats()
        addrs   = psutil.net_if_addrs()
        io_ctrs = psutil.net_io_counters(pernic=True)

        for name, stat in stats.items():
            io = io_ctrs.get(name)
            addr_list = []
            for a in addrs.get(name, []):
                addr_list.append({
                    "family":  str(a.family),
                    "address": a.address,
                    "netmask": a.netmask or "",
                    "broadcast": a.broadcast or "",
                })
            interfaces.append({
                "name":       name,
                "is_up":      stat.isup,
                "speed":      stat.speed,
                "mtu":        stat.mtu,
                "duplex":     str(stat.duplex),
                "addresses":  addr_list,
                "bytes_sent": io.bytes_sent if io else 0,
                "bytes_recv": io.bytes_recv if io else 0,
                "packets_sent": io.packets_sent if io else 0,
                "packets_recv": io.packets_recv if io else 0,
                "errin":      io.errin if io else 0,
                "errout":     io.errout if io else 0,
                "dropin":     io.dropin if io else 0,
                "dropout":    io.dropout if io else 0,
            })
        return interfaces

    # ── Network Connections ───────────────────────────────────────────────────
    def get_connections(self) -> list:
        if not PSUTIL_OK:
            return []
        results = []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            conns = []

        proc_map = {}
        try:
            for p in psutil.process_iter(["pid", "name"]):
                proc_map[p.info["pid"]] = p.info["name"]
        except Exception:
            pass

        for c in conns:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            pid   = c.pid

            # Threat heuristics
            flagged     = False
            flag_reason = ""
            anomaly_score = 0

            if c.raddr:
                rport = c.raddr.port
                rip   = c.raddr.ip
                if rport in SUSPICIOUS_PORTS:
                    flagged = True
                    flag_reason = f"Suspicious remote port {rport}"
                    anomaly_score = 85
                elif rip.startswith("0.") or rip == "0.0.0.0":
                    anomaly_score = 10
                elif not rip.startswith(("10.", "192.168.", "127.", "172.")):
                    anomaly_score = min(anomaly_score + 20, 60)

            if c.laddr and c.laddr.port in SUSPICIOUS_PORTS:
                flagged = True
                flag_reason = f"Listening on suspicious port {c.laddr.port}"
                anomaly_score = max(anomaly_score, 75)

            proc_name = proc_map.get(pid, "") if pid else ""
            if proc_name and proc_name.lower() in SUSPICIOUS_PROCS:
                flagged = True
                flag_reason = f"Suspicious process: {proc_name}"
                anomaly_score = max(anomaly_score, 90)

            conn_type = "TCP" if c.type and "SOCK_STREAM" in str(c.type) else "UDP"
            family    = "IPv6" if c.family and "AF_INET6" in str(c.family) else "IPv4"

            results.append({
                "type":          conn_type,
                "family":        family,
                "local_addr":    laddr,
                "remote_addr":   raddr,
                "status":        c.status or "-",
                "pid":           pid,
                "process":       proc_name,
                "flagged":       flagged,
                "flag_reason":   flag_reason,
                "anomaly_score": anomaly_score,
            })

        # Sort: flagged first, then by anomaly score
        results.sort(key=lambda x: (-x["flagged"], -x["anomaly_score"]))
        return results

    # ── Traffic Delta (bytes/s) ───────────────────────────────────────────────
    def get_traffic_delta(self) -> dict:
        global _last_net_io, _last_net_time
        if not PSUTIL_OK:
            return {"sent_ps": 0, "recv_ps": 0}
        current = psutil.net_io_counters()
        now     = time.time()
        if _last_net_io is None:
            _last_net_io  = current
            _last_net_time = now
            time.sleep(0.5)
            current = psutil.net_io_counters()
            now     = time.time()
        elapsed = now - _last_net_time
        if elapsed < 0.01:
            elapsed = 0.01
        sent_ps = max(0, (current.bytes_sent - _last_net_io.bytes_sent) / elapsed)
        recv_ps = max(0, (current.bytes_recv - _last_net_io.bytes_recv) / elapsed)
        _last_net_io  = current
        _last_net_time = now
        return {
            "sent_ps": round(sent_ps, 1),
            "recv_ps": round(recv_ps, 1),
            "total_sent": current.bytes_sent,
            "total_recv": current.bytes_recv,
        }

    # ── Processes ─────────────────────────────────────────────────────────────
    def get_all_processes(self) -> list:
        if not PSUTIL_OK:
            return []
        procs = []
        attrs = ["pid", "name", "username", "status", "cpu_percent",
                 "memory_percent", "memory_info", "create_time", "num_threads",
                 "nice", "exe", "cmdline"]
        try:
            for p in psutil.process_iter(attrs):
                try:
                    info = p.info
                    suspicious = info["name"].lower() in SUSPICIOUS_PROCS if info["name"] else False
                    create_dt  = datetime.datetime.fromtimestamp(info["create_time"]).strftime("%H:%M:%S") if info["create_time"] else "?"
                    mem_mb     = round(info["memory_info"].rss / 1048576, 1) if info["memory_info"] else 0
                    exe        = info.get("exe") or ""
                    procs.append({
                        "pid":        info["pid"],
                        "name":       info["name"] or "?",
                        "username":   info["username"] or "?",
                        "status":     info["status"] or "?",
                        "cpu":        round(info["cpu_percent"] or 0, 1),
                        "mem_pct":    round(info["memory_percent"] or 0, 2),
                        "mem_mb":     mem_mb,
                        "threads":    info["num_threads"] or 0,
                        "started":    create_dt,
                        "suspicious": suspicious,
                        "exe":        exe[:60],
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        procs.sort(key=lambda x: -x["cpu"])
        return procs

    def get_top_processes(self, n: int = 10) -> list:
        return self.get_all_processes()[:n]

    # ── Disk Info ─────────────────────────────────────────────────────────────
    def get_disk_info(self) -> list:
        if not PSUTIL_OK:
            return []
        disks = []
        try:
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({
                        "device":     part.device,
                        "mountpoint": part.mountpoint,
                        "fstype":     part.fstype,
                        "total":      usage.total,
                        "used":       usage.used,
                        "free":       usage.free,
                        "percent":    usage.percent,
                    })
                except PermissionError:
                    pass
        except Exception:
            pass
        return disks

    # ── Temperatures ─────────────────────────────────────────────────────────
    def get_temperatures(self) -> list:
        if not PSUTIL_OK:
            return []
        temps = []
        try:
            for name, entries in psutil.sensors_temperatures().items():
                for e in entries:
                    temps.append({
                        "label":   f"{name} — {e.label or 'Core'}",
                        "current": e.current,
                        "high":    e.high,
                        "critical":e.critical,
                    })
        except Exception:
            pass
        return temps

    # ── Host Info ─────────────────────────────────────────────────────────────
    def get_host_info(self) -> dict:
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            fqdn     = socket.getfqdn()
        except Exception:
            hostname = "unknown"
            local_ip = "unknown"
            fqdn     = "unknown"

        uname = platform.uname()
        return {
            "hostname":    hostname,
            "local_ip":    local_ip,
            "fqdn":        fqdn,
            "os":          f"{uname.system} {uname.release}",
            "os_version":  uname.version[:60] if uname.version else "",
            "machine":     uname.machine,
            "processor":   uname.processor or platform.processor() or "N/A",
            "python":      platform.python_version(),
            "node":        uname.node,
        }
