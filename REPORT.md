# Project Report: Selective Internet Kill Switch (Aegis)
**Subtitle: Application-Level Network Controller**

---

## 1. Abstract
The "Selective Internet Kill Switch - Aegis" is an application-level network control system designed to provide fine-grained, selective blocking of internet traffic. While traditional systems compel users to either entirely disconnect from the internet or remain fully connected without application control, this project bridges the gap. By leveraging Real-time DNS Packet Inspection via raw sockets and OS-level traffic filtering (`iptables`), Aegis enables users to selectively block domains (e.g., distracting social media) while allowing essential services (e.g., GitHub, development tools) to operate seamlessly. It features robust time-based access control and a centralized Dashboard UI for dynamic rule application.

## 2. Problem Statement
The typical user often requires uninterrupted internet access for work or study but struggles with digital distractions (e.g., streaming platforms, social media).
Current solutions are flawed:
1. **Hardware Kill Switches / Airplane Mode**: Entirely disables network connectivity, making productive web-dependent work impossible.
2. **Browser Extensions**: Easily bypassed by simply opening a different browser or using Incognito mode.
3. **Hosts File Modification**: Static and lacks dynamic intelligence or time-based conditions.

**Objective**: To build an OS-level, application-aware networking controller that intelligently drops packets for dynamically blacklisted domains without interrupting concurrent allowed traffic.

## 3. Methodology & Core Concept
The system architecture differentiates itself by focusing on **DNS Packet Interception & IP-level Blocking** rather than deep packet inspection (DPI) which is resource-heavy and complicated by SSL/HTTPS encryption.

### Process Flow:
1. **Packet Capture Engine**: Sniffs UDP Port 53 traffic using `Scapy`.
2. **Traffic Analyzer**: Extracts the queried domain name from the DNS Response.
3. **Rule Engine Evaluation**: Cross-references the queried domain against a dynamic list of active user rules (Always Block, Duration Timer, Scheduled Window).
4. **Action execution layer**: If a blocked domain is detected, the Engine maps the domain to the dynamically resolved IP address and instantly injects an `iptables DROP` rule to sequence the host's output table. 

This approach completely frustrates connection attempts to blocked domains across *all* applications (browsers, background apps, CLI tools) at the OS level, rendering HTTPS evasion moot since the TCP handshake itself is blocked.

## 4. System Architecture
```
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

## 5. Implementation
The solution was implemented in a Linux environment using Python, chosen for its networking libraries (`scapy`) and system interaction capabilities (`subprocess`, `psutil`).

### Components:
* **`killswitch.py` (Core Engine)**: Uses a multi-threaded approach. One thread constantly sniffs DNS packets over raw sockets. Another thread monitors time-based rules to automatically purge expired locks.
* **`app.py` (Traffic Controller Server)**: A backend REST API built using Flask.
* **Web UI`: A modern, dark-themed responsive frontend built using Glassmorphism design principles to act as the command center for rule deployment.

## 6. Results
The deployed Aegis System successfully demonstrated real-time traffic truncation. 
**Demo Output:**
- A user accesses `youtube.com` successfully.
- Via the Aegis Dashboard, a "15 Minute Duration Block" rule is applied to `youtube.com`.
- Subsequent user attempts to access YouTube are met with a generic OS network timeout (`ERR_CONNECTION_TIMED_OUT`) as `iptables` drops outgoing TCP requests to standard YouTube data IPs. 
- The live log terminal in the UI updates immediately: `🚫 BLOCKED traffic to 142.250.190.46 (matching youtube.com)`
- Once the 15-minute timer expires, the background monitoring thread purges the firewall rules, restoring service instantly.

## 7. Limitations & Future Work
* **Encrypted DNS Solutions**: Browsers using DNS-over-HTTPS (DoH) bypass standard UDP Port 53 sniffing. Mitigation includes applying known DoH provider IP blocks to force fallback to standard DNS.
* **Content Delivery Networks**: Large CDNs rotate IPs quickly; our script effectively detects and blocks them iteratively but can occasionally let initial ping packets through before the firewall chain updates.

## 8. Conclusion
The Selective Internet Kill Switch successfully merges network diagnostics, firewall configuration, and user-centric application control into a single unified product. Operating below the application layer, it provides robust, un-bypassable (for standard users) productivity enforcement, acting precisely like a proprietary commercial Parental Control or Enterprise Firewall system.
