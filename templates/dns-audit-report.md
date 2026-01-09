# DNS Security Audit Report

**Client:** {{CLIENT_NAME}}  
**Audit Date:** {{AUDIT_DATE}}  
**Prepared By:** Iron City IT Advisors - DNS Guard

---

## Executive Summary

This report presents the findings from the DNS security audit conducted for {{CLIENT_NAME}}. The assessment evaluated email authentication, DNSSEC implementation, and DNS infrastructure security.

### Overall DNS Security Score: {{DNS_SCORE}}/100

| Category | Status |
|----------|--------|
| Email Authentication (SPF/DKIM/DMARC) | {{EMAIL_AUTH_STATUS}} |
| DNSSEC | {{DNSSEC_STATUS}} |
| Zone Transfer Protection | {{ZONE_TRANSFER_STATUS}} |
| CAA Records | {{CAA_STATUS}} |

---

## Domains Audited

{{DOMAIN_LIST}}

---

## Findings by Domain

{{DOMAIN_FINDINGS}}

---

## Email Authentication

### SPF (Sender Policy Framework)

{{SPF_DETAILS}}

**Recommendation:** Ensure SPF record includes all legitimate email senders and ends with `-all` (hard fail) or `~all` (soft fail).

### DKIM (DomainKeys Identified Mail)

{{DKIM_DETAILS}}

**Recommendation:** Configure DKIM signing for all outbound email services.

### DMARC (Domain-based Message Authentication)

{{DMARC_DETAILS}}

**Recommendation:** Implement DMARC with `p=reject` policy after monitoring period.

---

## DNS Infrastructure

### DNSSEC Status

{{DNSSEC_DETAILS}}

**Recommendation:** Enable DNSSEC to protect against DNS spoofing and cache poisoning.

### Zone Transfer Security

{{ZONE_TRANSFER_DETAILS}}

**Recommendation:** Restrict AXFR to authorized secondary nameservers only.

### CAA (Certificate Authority Authorization)

{{CAA_DETAILS}}

**Recommendation:** Configure CAA records to restrict which CAs can issue certificates.

---

## Remediation Priority

### Critical (Immediate Action Required)
{{CRITICAL_ITEMS}}

### High Priority (Within 7 days)
{{HIGH_ITEMS}}

### Medium Priority (Within 30 days)
{{MEDIUM_ITEMS}}

### Low Priority (Within 90 days)
{{LOW_ITEMS}}

---

## Implementation Guide

### Adding SPF Record
```
example.com. IN TXT "v=spf1 include:_spf.google.com include:sendgrid.net -all"
```

### Adding DMARC Record
```
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

### Adding CAA Record
```
example.com. IN CAA 0 issue "letsencrypt.org"
example.com. IN CAA 0 issuewild ";"
```

---

**Report Prepared By:**  
Iron City IT Advisors - DNS Guard  
Fortify Your Frontline

**Contact:** security@ironcityit.com
