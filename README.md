# Selective Internet Kill Switch: Aegis 🛡️
**Subtitle:** Application-Level Network Controller

## Abstract
**Aegis** is an application-level network control system designed to provide fine-grained, selective blocking of internet traffic. While traditional systems compel users to either entirely disconnect from the internet or remain fully connected without application control, this project bridges the gap. 

By leveraging Real-time DNS Packet Inspection via raw sockets and OS-level traffic filtering (`iptables`), Aegis enables users to selectively block domains (e.g., distracting social media) while allowing essential services (e.g., GitHub, development tools) to operate seamlessly. It features robust time-based access control and a centralized command center UI for dynamic rule application.

## Problem Statement
The typical user often requires uninterrupted internet access for work or study but struggles with digital distractions (e.g., streaming platforms, social media). Current solutions are inherently flawed:
1. **Hardware Kill Switches / Airplane Mode**: Entirely disables network connectivity, making productive web-dependent work impossible.
2. **Browser Extensions**: Easily bypassed by simply opening a different browser or using Incognito mode.
3. **Hosts File Modification**: Static, cumbersome, and lacks dynamic intelligence or time-based conditions.

**Objective**: To build an OS-level, application-aware networking controller that intelligently drops packets for dynamically blacklisted domains without interrupting concurrent allowed traffic.

## How It Works (Methodology)
The system architecture differentiates itself by focusing on **DNS Packet Interception & IP-level Blocking** rather than resource-heavy Deep Packet Inspection (DPI).

### Process Flow:
1. **Packet Capture Engine**: Sniffs UDP Port 53 traffic using `scapy`.
2. **Traffic Analyzer**: Extracts the queried domain name from the DNS Response.
3. **Rule Engine Evaluation**: Cross-references the queried domain against a dynamic list of active user rules (e.g., Duration Timer, Scheduled Window).
4. **Action Execution Layer**: If a blocked domain is detected, the engine maps the domain to the dynamically resolved IP address and instantly injects an `iptables DROP` rule to the host's output table.

This completely halts connection attempts to blocked domains across *all* applications (browsers, background apps, CLI tools) at the OS level. HTTPS evasion is inherently mitigated since the TCP handshake itself is blocked.

## System Architecture
```text
[ User UI (Flask) ] <--> [ Rule Engine Database ]
                               |
                               v
[ Web Browser ] --> (DNS Query) --> [ DNS Server ]
                               |
                        [ Scapy Sniffer ]
                        (Intercepts Query)
                               |
                               v
                        [ Traffic Analyzer ]
                        (Checks against Rules)
                               |
                        (If Match Found)
                               |
                               v
                    [ OS Firewall (iptables) ]
                    (Injects DROP Rule for IP)
```

## Getting Started

### Prerequisites
- **OS**: Linux
- **Privileges**: Root access is required (for `scapy` packet sniffing and `iptables` modifications).
- **Environment**: Python 3.8+

### Installation
1. Clone the repository and navigate to the project directory.
2. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. *(Optional)* Set up DNSMasq if localized DNS routing is required:
   ```bash
   bash setup_dnsmasq_arch.sh
   ```

### Usage
1. Execute the Aegis launcher with superuser privileges:
   ```bash
   sudo python launch_aegis.py
   ```
2. The server will start, and the management dashboard will automatically open in your default browser.
3. Use the default login PIN: `2468`
4. From the dashboard, add sites to your blocklist with specific timers or constraints. The changes will instantly reflect at an OS-level!

## Credits
- K Nirmal Sesha Sai (24BYB1083)
- K Lokesh Reddy (24BYB1045)

## License
This project is submitted for academic purposes. Ownership is assigned to the instructor, while implementation credits remain with the authors.
``` 

Let me know if you would like any further changes or tweaks to this markdown!
