# **BaselFirewall - Attack Simulation Tests**

**Author:** Basel Abu-Radaha  
**Supervisor:** M. Nabarawi  
**College:** Hittien College
**Project:** BaselFirewall - Graduation Project  
**Date:** May 2025

---

## **Objective**
To test and validate the security features of the BaselFirewall against common network-based attacks using simulated tools.

---

## **Test Environment**

- **Firewall OS:** Kali Linux (BaselFirewall installed)  
- **Attacker Machine:** Metasploit VM (on same host network)  
- **Network:** Host-Only Adapter or NAT  
- **Firewall IP (Target):** `192.168.1.100` (example)  
- **Tools Used:** hping3, Snort, CLI/GUI logs

---

## **1. ICMP Ping Flood**

**Tool:** `hping3`  
**Command:**
```bash
hping3 --flood --icmp 192.168.1.100
```

**Expected Result:**
- Firewall logs ICMP flood attempt.
- Alerts triggered in GUI/CLI.
- System remains stable under load.

**Result:**  
✅ Successfully detected and blocked ping flood.

**Screenshot:**  
![ICMP Flood Log](../resources/screenshots/icmp_flood_log.png)

---

## **2. SYN Flood Attack**

**Tool:** `hping3`  
**Command:**
```bash
hping3 --flood -S -p 80 192.168.1.100
```

**Expected Result:**
- DoS protection module limits connections.
- Alerts logged with timestamp and source IP.
- Firewall stability maintained.

**Result:**  
✅ SYN packets blocked and logged.

**Screenshot:**  
![SYN Flood Log](../resources/screenshots/syn_flood_log.png)

---

## **3. Port Scan Detection**

**Tool:** `nmap`  
**Command:**
```bash
nmap -sS 192.168.1.100
```

**Expected Result:**
- IDS/IPS (Snort) detects scan.
- Intrusion log entry recorded.

**Result:**  
✅ Snort detected TCP scan and logged alert.

**Screenshot:**  
![Port Scan Alert](../resources/screenshots/port_scan_alert.png)

---

## **4. Unauthorized Access Attempt**

**Test:** Login with wrong credentials  
**Expected Result:**  
- Login blocked  
- Attempt logged in `firewall.log`  

**Result:**  
✅ Failed login attempts detected and recorded.

**Screenshot:**  
![Login Failure](../resources/screenshots/login_failure_log.png)

---

## **Conclusion**

All critical firewall protections were tested and passed:

- ✅ ICMP Flood  
- ✅ SYN Flood  
- ✅ Port Scanning  
- ✅ Authentication Logging  

BaselFirewall successfully blocked or logged all malicious activity.
