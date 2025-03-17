# Threat Vector:Simulated Attack Detection and Analysis


# Objective

The goal of this project was to simulate cybersecurity attacks within a controlled virtual environment, leveraging advanced monitoring and analysis tools to detect, analyze, and document attack progression. The focus was on understanding attacker behavior, enhancing detection capabilities, and refining incident response strategies.

# Skills Demonstrated

* Virtual Machine Setup and Configuration: Configured Windows 10 and Kali Linux virtual machines for attack simulation.

* Penetration Testing with Metasploit: Executed controlled attack scenarios using Metasploit, focusing on various attack vectors.

* Security Monitoring: Deployed and configured Sysmon for detailed Windows event logging, and integrated with Splunk for real-time monitoring and analysis.

* Alerting and Correlation: Created custom Splunk alerts and developed correlation searches to detect and validate attack behaviors.

* Incident Analysis: Conducted deep analysis of attack data, identifying Indicators of Compromise (IOCs) and evidential artifacts.

* Documentation: Authored detailed reports documenting the attack progression, findings, and insights.

* Professional Reporting: Produced professional, structured cybersecurity reports emphasizing correlation, timelines, and insights.

# Tools Used

* Windows 10 VM: Target environment for attack simulation.

* Kali Linux VM: Attack platform utilizing penetration testing tools.

* Metasploit Framework: Conducted penetration testing and exploited identified vulnerabilities.

* Sysmon: Configured for comprehensive system event monitoring on Windows.

* Splunk: Used for log collection, analysis, alerting, and correlation of security events.

# Project Workflow

1. Environment Setup

 * Configured Windows 10 and Kali Linux VMs.

 * Installed Sysmon on Windows with a detailed configuration to capture critical events (process creation, network connections, file modifications).

 * Integrated Sysmon with Splunk to ensure real-time log ingestion and visibility.


2. Attack Simulation

 * Performed multiple attack scenarios using Metasploit, including privilege escalation and credential dumping.

 * Maintained a controlled simulation, ensuring each attack vector was clearly understood and analyzed.


3. Monitoring and Detection

 * Configured Splunk to ingest and parse Sysmon logs for detailed analysis.

 * Set up custom alerts in Splunk to detect:

 * Unusual process creations.

 * Unauthorized access attempts.

 * Network connections to suspicious IPs.

 * Developed correlation searches to validate attacks by linking multiple data points (process, network, file activities).


4. Assumption and Correlation Process

 * Based on initial findings, assumptions were made regarding attack paths and methods.

 * Correlated diverse event types in Splunk to verify these assumptions, including:
 
 * Process Relationships: Tracing parent-child process relationships to detect malicious chains.

 * Network Indicators: Analyzing unusual outbound connections post-exploitation.

 * Privilege Escalation: Identifying privilege escalation attempts by analyzing token usage and process ownership changes.

 * Used these correlations to establish a clear timeline of attack progression and validate findings.


5. Documentation of Findings

 * Recorded each stage of the attack with detailed observations.

 * Highlighted key IOCs and evidential artifacts, such as suspicious hashes, registry modifications, or unique process patterns.

 * Documented how correlation strengthened the accuracy of attack assumptions.

 * Provided visual representations (where applicable) such as Splunk dashboard snapshots or Sysmon log excerpts.

# Results & Insights

* Detection Success: Successfully detected and documented key attack stages through Sysmon and Splunk.

* Identified Gaps: Discovered security gaps, particularly in privilege escalation detection.

* Alert Validation: Verified the effectiveness of Splunk alerts, reducing false positives through refined correlation logic.

* Behavioral Insights: Gained a deeper understanding of attacker behavior and the importance of system and process correlations.

* Correlation Value: Highlighted the critical role of correlation searches in validating attack paths and ensuring accurate analysis.

# Future Improvements

* Enhanced Sysmon Configurations: Broaden event capture to include more granular data for deeper insights.

* Refined Correlation Logic: Develop advanced Splunk correlation rules to reduce false positives and enhance detection depth.

* Integrate Additional Tools: Explore integrating Suricata or Zeek for expanded detection capabilities.

* Diverse Attack Simulations: Conduct varied simulations to cover a broader threat landscape.

* Automation: Implement automated responses for specific detected alerts to accelerate incident handling.

# Conclusion

This project provided critical hands-on experience in simulating, detecting, and analyzing cybersecurity attacks. The integration of Sysmon with Splunk proved invaluable for monitoring and responding to threats. The documentation process, particularly correlation validation, emphasized the importance of detailed analysis and structured reporting. This project not only strengthened technical capabilities but also highlighted the value of a methodical and professional approach to cybersecurity investigations.

# Screenshots

# Pre-Attack Reconnaissance

![Nmap Scan](https://github.com/Mihindig/Threat-Vector/blob/main/Nmap%20Scan.png)

![Connectivity Check](https://github.com/Mihindig/Threat-Vector/blob/main/Connectivity%20Check.png)

# Payload Creation & Delivery

![Payload Creation & Generation](https://github.com/Mihindig/Threat-Vector/blob/main/Payload%20Generation.png)

# HTTP Server Setup

![http server before](https://github.com/Mihindig/Threat-Vector/blob/main/http%20server%20before.png)

![http server after](https://github.com/Mihindig/Threat-Vector/blob/main/http%20server%20after.png)

# File Delivery Confirmation

![file delivery confirmation chrome](https://github.com/Mihindig/Threat-Vector/blob/main/File%20Delivery%20Confirmation%20chrome.png)

![file delivery confirmation downloads](https://github.com/Mihindig/Threat-Vector/blob/main/File%20Delivery%20Confirmation%20downloads.png)

# Exploitation & Gaining Access

![metaspoilt setup](https://github.com/Mihindig/Threat-Vector/blob/main/metasploit%20setup.png)

![successfl exploitation](https://github.com/Mihindig/Threat-Vector/blob/main/successful%20exploitation.png)

![session interaction](https://github.com/Mihindig/Threat-Vector/blob/main/session%20interaction.png)

# Privilege Escalation

![bypassing uac](https://github.com/Mihindig/Threat-Vector/blob/main/bypassing%20UAC.png)

![systemaccessconfirmation](https://github.com/Mihindig/Threat-Vector/blob/main/System%20Access%20Confirmation.png)

# Persistence & Migration

![process migration](https://github.com/Mihindig/Threat-Vector/blob/main/process%20migration.png)

#  Credential Dumping & Post-Exploitation

![Mimikatz](https://github.com/Mihindig/Threat-Vector/blob/main/Mimikatz.png)

![mimikatz kiwi](https://github.com/Mihindig/Threat-Vector/blob/main/mimikatz%20kiwi.png)

![enumeration 1](https://github.com/Mihindig/Threat-Vector/blob/main/enumeration%201.png)

![enumeration 2](https://github.com/Mihindig/Threat-Vector/blob/main/enumeration%202.png)

# Initial Attack Detection

![1](https://github.com/Mihindig/Threat-Vector/blob/main/1.png)

* Initial detection of suspicious executable (.exe) in the Downloads folder. The medium integrity level suggests it wasn’t executed with elevated privileges, but the location and naming convention align with common attacker tactics to disguise payloads.
  
# Privilege Escalation & Enumeration

![2](https://github.com/Mihindig/Threat-Vector/blob/main/2.png)

![3](https://github.com/Mihindig/Threat-Vector/blob/main/3.png)

![4](https://github.com/Mihindig/Threat-Vector/blob/main/4.png)

![5](https://github.com/Mihindig/Threat-Vector/blob/main/5.png)

* Multiple elevated process creations were detected, including suspicious use of netstat for network scanning, fodhelper.exe for UAC bypass, and csc.exe for on-the-fly payload compilation. These stages show the attacker's progression towards privilege escalation and establishing persistence.

# Credential Access & LSASS Interaction

![6](https://github.com/Mihindig/Threat-Vector/blob/main/6.png)

![7](https://github.com/Mihindig/Threat-Vector/blob/main/7.png)

![8](https://github.com/Mihindig/Threat-Vector/blob/main/8.png)

* Alerts detected memory access attempts targeting critical system processes like lsass.exe and winlogon.exe. These are typical indicators of credential dumping activities. The transition from empty user fields to SYSTEM privileges demonstrates successful privilege escalation.

# Splunk Dashboard with Correlated Events

![dashborad 1](https://github.com/Mihindig/Threat-Vector/blob/main/dashboard%201.png)

![dashborad 2](https://github.com/Mihindig/Threat-Vector/blob/main/dashboard%202.png)

* The Splunk dashboard consolidates key correlation queries, highlighting the attacker's movement from initial payload execution to privilege escalation and credential access. This comprehensive view demonstrates how different event types were correlated to reconstruct the attack timeline.
  
# Threat Validation via VirusTotal

![kali linux IP validation](https://github.com/Mihindig/Threat-Vector/blob/main/kali%20linux%20IP%20validation.png)

* Validated the Kali Linux attacker's IP address using VirusTotal, confirming it as a private and non-malicious address. This step ensured that the simulated attack remained within the controlled environment and did not trigger external threat indicators

![malicious payload detection](https://github.com/Mihindig/Threat-Vector/blob/main/malicious%20payload%20detection.png)

![payload](https://github.com/Mihindig/Threat-Vector/blob/main/payload.png)

* The generated .exe payload was analyzed through VirusTotal, where it was flagged by 59 out of 73 security vendors with a 100% severity rating, confirming its classification as a Windows.Trojan.Metasploit. This validated the payload’s malicious nature and reinforced the effectiveness of detection mechanisms.

# Post-Exploitation Remediation and Cleanup

![network isolation](https://github.com/Mihindig/Threat-Vector/blob/main/network%20isolation.png)

* Isolated the compromised Windows machine by configuring it to a host-only adapter, ensuring it was disconnected from external networks to prevent any outbound communication or data exfiltration.
  
![task manager](https://github.com/Mihindig/Threat-Vector/blob/main/task%20manager.png)

![deleted .exe](https://github.com/Mihindig/Threat-Vector/blob/main/deleted%20.exe.png)

![empty recycle](https://github.com/Mihindig/Threat-Vector/blob/main/empty%20recycle.png)

* Manually terminated the malicious .exe process and ensured thorough removal by deleting it from the Downloads folder and permanently clearing it from the Recycle Bin, ensuring no residual presence.

# Proactive Defense

![firewall](https://github.com/Mihindig/Threat-Vector/blob/main/firewall%20rule.png)

* Configured a Windows Firewall outbound rule to block TCP traffic on port 4444, which was previously used for the Command and Control (C2) connection. This ensures any future unauthorized attempts to establish similar connections are effectively blocked.

#  System Security Re-Enablement

![windows defender](https://github.com/Mihindig/Threat-Vector/blob/main/defender.png)

![quick scan](https://github.com/Mihindig/Threat-Vector/blob/main/quick%20scan.png)

* Re-enabled Windows Defender's virus and threat protection and performed a quick system scan to identify and eliminate any lingering malicious artifacts.

# Persistence Mechanism Check

![9](https://github.com/Mihindig/Threat-Vector/blob/main/9.png)

![10](https://github.com/Mihindig/Threat-Vector/blob/main/10.png)

![startup](https://github.com/Mihindig/Threat-Vector/blob/main/empty%20startup.png)

* Checked critical registry run keys and the Startup folder for any signs of persistence mechanisms. No unauthorized entries were detected, confirming successful malware removal.

# Network Verification

![findstr](https://github.com/Mihindig/Threat-Vector/blob/main/findstr.png)

* Verified network status by executing netstat -ano | findstr 4444, confirming that the malicious listener process on port 4444 was successfully terminated and no longer active.

# Resources

### https://www.microsoft.com/en-ca/software-download/windows10
### https://www.virtualbox.org
### https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
### https://github.com/olafhartong/sysmon-modular
### https://www.splunk.com
### https://www.virustotal.com
### https://www.kali.org

# License:
© Mihindig 2025. All rights reserved.

This repository is for educational purposes only. Unauthorized use, redistribution, or commercial use of this code is prohibited without explicit permission from the author. Please do not copy or redistribute without providing appropriate credit.


# Contact:

<a href="https://www.linkedin.com/in/mihindi-gunawardana-44a0a432b/" target="_blank">
  <img src="https://img.shields.io/badge/-LinkedIn-0072b1?&style=for-the-badge&logo=linkedin&logoColor=white" />
</a>

