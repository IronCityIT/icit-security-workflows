# Iron City Purple Team Exercise Framework
## Based on SCYTHE PTEF v3

---

# CLIENT: [CLIENT NAME]
# ENGAGEMENT: [ENGAGEMENT NAME]
# DATE: [DATE]
# LEAD: [YOUR NAME]

---

## 1. EXECUTIVE SUMMARY

This Purple Team Exercise tests [CLIENT NAME]'s security controls against realistic adversary tactics, techniques, and procedures (TTPs). Unlike traditional penetration testing, this collaborative exercise involves both offensive (Red) and defensive (Blue) teams working together to identify detection gaps and improve security posture.

**Key Objectives:**
- Test detection capabilities against [THREAT ACTOR / TTP SET]
- Validate security control effectiveness
- Identify gaps in people, process, and technology
- Provide actionable remediation recommendations

---

## 2. SCOPE

### In Scope:
- [ ] Internal network (specify subnets)
- [ ] External perimeter
- [ ] Cloud environment (AWS/Azure/GCP)
- [ ] Specific applications: [LIST]
- [ ] Endpoints (Windows/Linux/Mac)

### Out of Scope:
- [ ] Production systems (if applicable)
- [ ] Third-party systems
- [ ] Physical security
- [ ] Social engineering

### Rules of Engagement:
- Testing window: [START DATE] to [END DATE]
- Testing hours: [HOURS] [TIMEZONE]
- Emergency contact: [NAME] [PHONE]
- Stop conditions: [DEFINE]

---

## 3. THREAT INTELLIGENCE

### 3.1 Adversary Profile

Based on CTI analysis, the following threat actors have opportunity, intent, and capability to target [CLIENT NAME]:

| Threat Actor | Industry Target | Primary TTPs | Confidence |
|--------------|-----------------|--------------|------------|
| [APT GROUP] | [INDUSTRY] | [TECHNIQUES] | High/Medium/Low |

### 3.2 Selected TTPs for Emulation

| MITRE ID | Technique | Rationale |
|----------|-----------|-----------|
| T1566.001 | Spearphishing Attachment | Common initial access |
| T1059.001 | PowerShell | Post-exploitation |
| T1003.001 | LSASS Memory | Credential access |
| T1021.001 | Remote Desktop | Lateral movement |
| T1547.001 | Registry Run Keys | Persistence |

---

## 4. EXERCISE EXECUTION

### 4.1 Phase 1: Initial Access

| Step | TTP | Red Team Action | Expected Blue Detection | Actual Result |
|------|-----|-----------------|------------------------|---------------|
| 1.1 | T1566.001 | Send phishing email with malicious attachment | Email gateway alert, EDR alert on execution | ☐ Detected ☐ Missed |
| 1.2 | T1204.002 | User executes payload | EDR process execution alert | ☐ Detected ☐ Missed |

**Notes:**
```
[Document observations, timing, specific alerts]
```

### 4.2 Phase 2: Execution & Discovery

| Step | TTP | Red Team Action | Expected Blue Detection | Actual Result |
|------|-----|-----------------|------------------------|---------------|
| 2.1 | T1059.001 | PowerShell reconnaissance | SIEM PowerShell logging, EDR | ☐ Detected ☐ Missed |
| 2.2 | T1082 | System information discovery | Process monitoring | ☐ Detected ☐ Missed |
| 2.3 | T1016 | Network configuration discovery | Command line logging | ☐ Detected ☐ Missed |

**Notes:**
```
[Document observations]
```

### 4.3 Phase 3: Credential Access

| Step | TTP | Red Team Action | Expected Blue Detection | Actual Result |
|------|-----|-----------------|------------------------|---------------|
| 3.1 | T1003.001 | LSASS memory dump | EDR, Sysmon Event 10 | ☐ Detected ☐ Missed |
| 3.2 | T1558.003 | Kerberoasting | SIEM authentication logs | ☐ Detected ☐ Missed |

**Notes:**
```
[Document observations]
```

### 4.4 Phase 4: Lateral Movement

| Step | TTP | Red Team Action | Expected Blue Detection | Actual Result |
|------|-----|-----------------|------------------------|---------------|
| 4.1 | T1021.001 | RDP to target system | SIEM login events | ☐ Detected ☐ Missed |
| 4.2 | T1021.002 | SMB/Admin shares | Network monitoring | ☐ Detected ☐ Missed |

**Notes:**
```
[Document observations]
```

### 4.5 Phase 5: Persistence

| Step | TTP | Red Team Action | Expected Blue Detection | Actual Result |
|------|-----|-----------------|------------------------|---------------|
| 5.1 | T1547.001 | Registry Run Key | EDR, Sysmon Event 13 | ☐ Detected ☐ Missed |
| 5.2 | T1053.005 | Scheduled Task | SIEM task creation logs | ☐ Detected ☐ Missed |

**Notes:**
```
[Document observations]
```

---

## 5. DETECTION COVERAGE MATRIX

| MITRE Tactic | Techniques Tested | Detected | Missed | Coverage |
|--------------|-------------------|----------|--------|----------|
| Initial Access | 2 | | | % |
| Execution | 3 | | | % |
| Persistence | 2 | | | % |
| Privilege Escalation | 1 | | | % |
| Defense Evasion | 2 | | | % |
| Credential Access | 2 | | | % |
| Discovery | 3 | | | % |
| Lateral Movement | 2 | | | % |
| **TOTAL** | **17** | **X** | **X** | **X%** |

---

## 6. FINDINGS

### 6.1 Critical Findings

| ID | Finding | TTP | Risk | Recommendation |
|----|---------|-----|------|----------------|
| C-01 | [Description] | [TTP] | Critical | [Remediation] |

### 6.2 High Findings

| ID | Finding | TTP | Risk | Recommendation |
|----|---------|-----|------|----------------|
| H-01 | [Description] | [TTP] | High | [Remediation] |

### 6.3 Medium Findings

| ID | Finding | TTP | Risk | Recommendation |
|----|---------|-----|------|----------------|
| M-01 | [Description] | [TTP] | Medium | [Remediation] |

### 6.4 Low Findings

| ID | Finding | TTP | Risk | Recommendation |
|----|---------|-----|------|----------------|
| L-01 | [Description] | [TTP] | Low | [Remediation] |

---

## 7. REMEDIATION ROADMAP

### Immediate (0-30 days)
- [ ] [Action item 1]
- [ ] [Action item 2]

### Short-term (30-90 days)
- [ ] [Action item 1]
- [ ] [Action item 2]

### Long-term (90+ days)
- [ ] [Action item 1]
- [ ] [Action item 2]

---

## 8. LESSONS LEARNED

### What Worked Well:
1. [Item]
2. [Item]

### Areas for Improvement:
1. [Item]
2. [Item]

### Recommended Follow-up:
1. Retest in [X] months
2. Expand scope to include [X]
3. [Other recommendations]

---

## 9. APPENDICES

### A. Tools Used
- Atomic Red Team
- Empire (BC-Security)
- [Other tools]

### B. Detection Rules Created/Updated
```yaml
# Example Wazuh rule
<rule id="100001" level="12">
  <if_sid>5710</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">\\lsass.dmp$</field>
  <description>LSASS memory dump detected - possible credential theft</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
</rule>
```

### C. IOCs Generated
| Type | Value | Context |
|------|-------|---------|
| Hash | [SHA256] | Test payload |
| IP | [IP] | C2 server |
| Domain | [Domain] | Staging |

### D. Timeline of Events
| Time | Action | Detection |
|------|--------|-----------|
| 09:00 | Exercise start | N/A |
| 09:15 | [Action] | [Detection] |

---

## 10. SIGN-OFF

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Red Team Lead | | | |
| Blue Team Lead | | | |
| Client POC | | | |
| Iron City IT | | | |

---

*This document is confidential and intended for [CLIENT NAME] only.*

*Iron City IT Advisors - Blue-Collar Security*
