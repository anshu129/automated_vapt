"""Generate full nmap parameter reference from official help structure."""

from pathlib import Path
import textwrap

import yaml

NMAP_VERSION = "7.99SVN"

GROUPS = [
    {
        "id": "TARGET_SPECIFICATION",
        "title": "Target specification",
        "description": "Can pass hostnames, IP addresses, networks, etc.",
        "parameters": [
            ("target", "{target}", "Hostname, IP, CIDR, or range. Ex: scanme.nmap.org, 192.168.0.0/24"),
            ("iL", "-iL <inputfilename>", "Input from list of hosts/networks"),
            ("iR", "-iR <num hosts>", "Choose random targets"),
            ("exclude", "--exclude <host1[,host2]...>", "Exclude hosts/networks from scan"),
            ("excludefile", "--excludefile <exclude_file>", "Exclude list from file"),
        ],
    },
    {
        "id": "HOST_DISCOVERY",
        "title": "Host discovery",
        "parameters": [
            ("sL", "-sL", "List scan — list targets without sending packets"),
            ("sn", "-sn", "Ping scan — disable port scan (host discovery only)"),
            ("Pn", "-Pn", "Treat all hosts as online — skip host discovery"),
            ("PS", "-PS[portlist]", "TCP SYN discovery to given ports"),
            ("PA", "-PA[portlist]", "TCP ACK discovery to given ports"),
            ("PU", "-PU[portlist]", "UDP discovery to given ports"),
            ("PY", "-PY[portlist]", "SCTP discovery to given ports"),
            ("PE", "-PE", "ICMP echo request discovery"),
            ("PP", "-PP", "ICMP timestamp request discovery"),
            ("PM", "-PM", "ICMP netmask request discovery"),
            ("PO", "-PO[protocol list]", "IP protocol ping"),
            ("n", "-n", "Never do DNS resolution"),
            ("R", "-R", "Always resolve DNS"),
            ("dns-servers", "--dns-servers <serv1[,serv2]...>", "Specify custom DNS servers"),
            ("system-dns", "--system-dns", "Use OS DNS resolver"),
            ("traceroute", "--traceroute", "Trace hop path to each host"),
            ("disable-arp-ping", "--disable-arp-ping", "No ARP/ND ping on local ethernet"),
        ],
    },
    {
        "id": "SCAN_TECHNIQUES",
        "title": "Scan techniques",
        "parameters": [
            ("sS", "-sS", "TCP SYN scan (default for privileged users)"),
            ("sT", "-sT", "TCP connect scan"),
            ("sA", "-sA", "TCP ACK scan"),
            ("sW", "-sW", "TCP Window scan"),
            ("sM", "-sM", "TCP Maimon scan"),
            ("sU", "-sU", "UDP scan"),
            ("sN", "-sN", "TCP Null scan"),
            ("sF", "-sF", "TCP FIN scan"),
            ("sX", "-sX", "TCP Xmas scan"),
            ("scanflags", "--scanflags <flags>", "Customize TCP scan flags"),
            ("sI", "-sI <zombie host[:probeport]>", "Idle scan"),
            ("sY", "-sY", "SCTP INIT scan"),
            ("sZ", "-sZ", "SCTP COOKIE-ECHO scan"),
            ("sO", "-sO", "IP protocol scan"),
            ("b", "-b <FTP relay host>", "FTP bounce scan"),
        ],
    },
    {
        "id": "PORT_SPECIFICATION",
        "title": "Port specification and scan order",
        "parameters": [
            ("p", "-p <port ranges>", "Only scan specified ports. Ex: -p22; -p1-65535; -p U:53,T:80"),
            ("exclude-ports", "--exclude-ports <port ranges>", "Exclude ports from scanning"),
            ("F", "-F", "Fast mode — scan fewer ports than default"),
            ("r", "-r", "Scan ports sequentially — do not randomize"),
            ("top-ports", "--top-ports <number>", "Scan N most common ports"),
            ("port-ratio", "--port-ratio <ratio>", "Scan ports more common than ratio"),
        ],
    },
    {
        "id": "SERVICE_VERSION",
        "title": "Service/version detection",
        "parameters": [
            ("sV", "-sV", "Probe open ports for service/version info"),
            ("version-intensity", "--version-intensity <0-9>", "Version probe intensity level"),
            ("version-light", "--version-light", "Limit to likely probes (intensity 2)"),
            ("version-all", "--version-all", "Try every probe (intensity 9)"),
            ("version-trace", "--version-trace", "Show detailed version scan activity"),
        ],
    },
    {
        "id": "SCRIPT_SCAN",
        "title": "Script scan (NSE)",
        "parameters": [
            ("sC", "-sC", "Equivalent to --script=default"),
            ("script", "--script=<Lua scripts>", "Comma-separated scripts, directories, or categories"),
            ("script-args", "--script-args=<n1=v1,...>", "Arguments to NSE scripts"),
            ("script-args-file", "--script-args-file=filename", "NSE args from file"),
            ("script-trace", "--script-trace", "Show all data sent and received"),
            ("script-updatedb", "--script-updatedb", "Update the script database"),
            ("script-help", "--script-help=<Lua scripts>", "Show help about scripts"),
        ],
    },
    {
        "id": "OS_DETECTION",
        "title": "OS detection",
        "parameters": [
            ("O", "-O", "Enable OS detection"),
            ("osscan-limit", "--osscan-limit", "Limit OS detection to promising targets"),
            ("osscan-guess", "--osscan-guess", "Guess OS more aggressively"),
        ],
    },
    {
        "id": "TIMING_PERFORMANCE",
        "title": "Timing and performance",
        "parameters": [
            ("T0", "-T0", "Paranoid timing template"),
            ("T1", "-T1", "Sneaky timing template"),
            ("T2", "-T2", "Polite timing template"),
            ("T3", "-T3", "Normal timing template (default)"),
            ("T4", "-T4", "Aggressive timing template"),
            ("T5", "-T5", "Insane timing template"),
            ("min-hostgroup", "--min-hostgroup/--max-hostgroup <size>", "Parallel host scan group sizes"),
            ("min-parallelism", "--min-parallelism/--max-parallelism <n>", "Probe parallelization"),
            ("rtt-timeout", "--min-rtt-timeout/--max-rtt-timeout/initial-rtt-timeout <time>", "Probe RTT timeouts"),
            ("max-retries", "--max-retries <tries>", "Cap port scan probe retransmissions"),
            ("host-timeout", "--host-timeout <time>", "Give up on target after duration"),
            ("scan-delay", "--scan-delay/--max-scan-delay <time>", "Delay between probes"),
            ("min-rate", "--min-rate <number>", "Send packets no slower than N per second"),
            ("max-rate", "--max-rate <number>", "Send packets no faster than N per second"),
        ],
    },
    {
        "id": "FIREWALL_EVASION",
        "title": "Firewall/IDS evasion and spoofing",
        "platform_policy": "Documented for completeness. Automated scans use only scope-authorized options; decoy/spoof flags require explicit approval.",
        "parameters": [
            ("f", "-f", "Fragment packets"),
            ("mtu", "--mtu <val>", "Fragment packets with given MTU"),
            ("D", "-D <decoy1,decoy2[,ME],...>", "Cloak scan with decoys"),
            ("S", "-S <IP_Address>", "Spoof source address"),
            ("e", "-e <iface>", "Use specified interface"),
            ("source-port", "-g/--source-port <portnum>", "Use given source port"),
            ("proxies", "--proxies <url1,[url2],...>", "Relay through HTTP/SOCKS4 proxies"),
            ("data", "--data <hex string>", "Append custom payload to packets"),
            ("data-string", "--data-string <string>", "Append custom ASCII payload"),
            ("data-length", "--data-length <num>", "Append random data to packets"),
            ("ip-options", "--ip-options <options>", "Send packets with specified IP options"),
            ("ttl", "--ttl <val>", "Set IP TTL field"),
            ("spoof-mac", "--spoof-mac <mac/prefix/vendor>", "Spoof MAC address"),
            ("badsum", "--badsum", "Send packets with bogus checksum"),
        ],
    },
    {
        "id": "OUTPUT",
        "title": "Output",
        "parameters": [
            ("oN", "-oN <file>", "Normal format output"),
            ("oX", "-oX <file>", "XML format output"),
            ("oS", "-oS <file>", "Script kiddie format output"),
            ("oG", "-oG <file>", "Grepable format output"),
            ("oA", "-oA <basename>", "Output in normal, XML, and grepable formats"),
            ("v", "-v", "Increase verbosity"),
            ("d", "-d", "Increase debugging level"),
            ("reason", "--reason", "Display reason a port is in a particular state"),
            ("open", "--open", "Only show open (or possibly open) ports"),
            ("packet-trace", "--packet-trace", "Show all packets sent and received"),
            ("iflist", "--iflist", "Print host interfaces and routes"),
            ("append-output", "--append-output", "Append to output files"),
            ("resume", "--resume <filename>", "Resume aborted scan"),
            ("noninteractive", "--noninteractive", "Disable runtime keyboard interactions"),
            ("stylesheet", "--stylesheet <path/URL>", "XSL stylesheet for XML to HTML"),
            ("webxml", "--webxml", "Reference stylesheet from Nmap.Org"),
            ("no-stylesheet", "--no-stylesheet", "Do not associate XSL with XML output"),
        ],
    },
    {
        "id": "MISC",
        "title": "Miscellaneous",
        "parameters": [
            ("6", "-6", "Enable IPv6 scanning"),
            ("A", "-A", "OS detection, version detection, script scan, and traceroute"),
            ("datadir", "--datadir <dirname>", "Custom Nmap data file location"),
            ("send-eth", "--send-eth", "Send using raw ethernet frames"),
            ("send-ip", "--send-ip", "Send using raw IP packets"),
            ("privileged", "--privileged", "Assume user is fully privileged"),
            ("unprivileged", "--unprivileged", "Assume user lacks raw socket privileges"),
            ("V", "-V", "Print version number"),
            ("h", "-h", "Print help summary"),
        ],
    },
]

# Platform when_to_use / operational_triggers for adaptive flags
ADAPTIVE = {
    "Pn": {
        "when_to_use": "ICMP blocked or firewall drops ping; host may still have open ports.",
        "operational_triggers": ["icmp_blocked", "firewall_inferred"],
        "adaptive_rule_id": "param-nmap-skip-ping-icmp",
        "doc_url": "https://nmap.org/book/man-host-discovery.html",
    },
    "disable-arp-ping": {
        "when_to_use": "Proxy ARP or LAN false positives; disable implicit ARP discovery on ethernet.",
        "operational_triggers": ["proxy_arp_suspected", "local_network_target", "firewall_inferred"],
        "adaptive_rule_id": "param-nmap-disable-arp-ping-proxy-arp",
        "doc_url": "https://nmap.org/book/man-host-discovery.html",
    },
    "sS": {
        "when_to_use": "Filtered ports or stateful firewall; SYN scan without completing handshake.",
        "operational_triggers": ["filtered_ports_observed", "firewall_inferred"],
        "adaptive_rule_id": "param-nmap-tcp-syn-filtered",
    },
    "sV": {
        "when_to_use": "SERVICE_IDENTIFICATION capability; default in platform manifest base_args.",
        "operational_triggers": ["manifest_base"],
        "platform_default": True,
    },
    "T2": {
        "when_to_use": "Rate limiting or IDS throttling observed on prior probes.",
        "operational_triggers": ["rate_limited"],
        "adaptive_rule_id": "param-nmap-timing-rate-limited",
    },
    "host-timeout": {
        "when_to_use": "HIGH_LATENCY profile or slow/unresponsive targets.",
        "operational_triggers": ["previous_timeouts"],
        "adaptive_rule_id": "param-nmap-host-timeout-latency",
    },
    "oX": {
        "when_to_use": "Platform parser consumes XML on stdout (-oX -).",
        "operational_triggers": ["manifest_base"],
        "platform_default": True,
    },
    "reason": {
        "when_to_use": "Evidence quality debugging when port states are ambiguous (filtered vs closed).",
        "operational_triggers": ["filtered_ports_observed", "inconclusive_dns"],
    },
    "F": {
        "when_to_use": "Initial PORT_DISCOVERY pass on large target sets before full port sweep.",
        "operational_triggers": ["large_target_set", "cidr_scope"],
    },
    "top-ports": {
        "when_to_use": "Fast first pass; scan most common ports before full range.",
        "operational_triggers": ["large_target_set"],
    },
    "sn": {
        "when_to_use": "HOST_REACHABILITY_ASSESSMENT only; no port scan noise.",
        "operational_triggers": ["passive_only"],
    },
    "max-rate": {
        "when_to_use": "Cap probe rate when rate_limited or fragile production target.",
        "operational_triggers": ["rate_limited", "waf_detected"],
    },
    "send-ip": {
        "when_to_use": "Alternative to ARP on LAN when --disable-arp-ping set; use IP-level probes.",
        "operational_triggers": ["proxy_arp_suspected", "local_network_target"],
    },
}


def build_group(group: dict) -> dict:
    params = []
    for pid, flags, desc in group["parameters"]:
        entry = {
            "id": pid,
            "flags": [flags] if isinstance(flags, str) else flags,
            "description": desc,
            "rationale": f"Official nmap {NMAP_VERSION} help: {desc}",
        }
        if pid in ADAPTIVE:
            entry.update(ADAPTIVE[pid])
        params.append(entry)
    out = {
        "id": group["id"],
        "title": group["title"],
        "parameters": params,
    }
    if group.get("description"):
        out["description"] = group["description"]
    if group.get("platform_policy"):
        out["platform_policy"] = group["platform_policy"]
    return out


def main() -> None:
    doc = {
        "version": "2.0",
        "category": "host_service",
        "tools": {
            "nmap": {
                "tool_version": NMAP_VERSION,
                "official_docs": [
                    "https://nmap.org",
                    "https://nmap.org/book/man.html",
                    "https://nmap.org/book/man-host-discovery.html",
                    "https://nmap.org/book/man-port-scanning-techniques.html",
                    "https://nmap.org/book/man-performance.html",
                ],
                "usage": "nmap [Scan Type(s)] [Options] {target specification}",
                "summary": "Network mapper for host discovery, port scanning, service/version detection, NSE scripts, and OS fingerprinting.",
                "examples": [
                    "nmap -v -A scanme.nmap.org",
                    "nmap -v -sn 192.168.0.0/16 10.0.0.0/8",
                    "nmap -v -iR 10000 -Pn -p 80",
                ],
                "platform_manifest_base_args": ["-sV", "-oX", "-", "{target}"],
                "parameter_groups": [build_group(g) for g in GROUPS],
            }
        },
    }
    out = Path("config/parameters/references/nmap.yaml")
    header = (
        "# Full nmap parameter catalog — mirrors nmap -h / man page structure\n"
        f"# Generated from official Nmap {NMAP_VERSION} help; re-run scripts/generate_nmap_reference.py to refresh\n"
    )
    out.write_text(
        header + yaml.dump(doc, sort_keys=False, allow_unicode=True, width=120),
        encoding="utf-8",
    )
    n_params = sum(len(g["parameters"]) for g in doc["tools"]["nmap"]["parameter_groups"])
    print(f"Wrote {out} with {n_params} parameters in {len(GROUPS)} groups")


if __name__ == "__main__":
    main()
