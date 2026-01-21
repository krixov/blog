---
title: "Threat Modeling a Web App: STRIDE to Controls"
date: "2024-12-02"
excerpt: "From data flow diagrams to security controls, with templates you can reuse."
featured: "/images/test1.jpg"
tags:
  - threat-modeling
  - stride
  - security
  - web
---

## Why threat modeling is practical

Threat modeling is not a compliance task. It is a shortcut to finding real risks before attackers do. The goal is to map assets, understand trust boundaries, and make controls explicit.

## Step 1: Draw a data flow diagram

Start simple. You can refine later.

```
[User]
   |
   v
[Web Frontend] ---> [API] ---> [Database]
   |                   |
   v                   v
[CDN]              [Blob Storage]
```

Identify trust boundaries, like the boundary between public traffic and internal services.

## Step 2: Enumerate assets

- User credentials and session tokens
- PII in the database
- Payment data in third-party providers
- Admin actions and audit logs

## Step 2.1: Define trust boundaries and entry points

Document where data crosses trust boundaries. Typical entry points:

- Public web endpoints
- Mobile API endpoints
- Admin consoles and internal tools
- Webhooks from third-party providers

If the boundary is unclear, draw it explicitly in the diagram and annotate it with a label like "public internet" or "internal network."

## Step 2.2: Classify data

Data classification helps you prioritize controls.

| Data type | Confidentiality | Example |
| --- | --- | --- |
| Public | Low | Marketing pages |
| Internal | Medium | Feature flags |
| Sensitive | High | PII, auth tokens |
| Regulated | High | Payment data |

## Step 3: Apply STRIDE

STRIDE helps you brainstorm threats by category.

| Threat | Example | Control |
| --- | --- | --- |
| Spoofing | Stolen session cookie | HttpOnly cookies, MFA |
| Tampering | Modified API payload | HMAC, request signing |
| Repudiation | Admin denies action | Immutable audit logs |
| Info disclosure | Leaked PII | Field-level encryption |
| Denial of service | Abuse on login | Rate limiting, WAF |
| Elevation | User becomes admin | RBAC, least privilege |

## Step 4: Write abuse cases

- Attackers brute force login and reuse leaked credentials.
- A support agent exports too much data.
- A misconfigured bucket exposes private documents.

Abuse cases should be short, specific, and testable.

## Step 5: Map to concrete controls

A control is an implementation detail, not a wish. Example controls:

- Strict schema validation at the API layer.
- CSRF protection on state-changing requests.
- CSP and `X-Frame-Options` to reduce XSS and clickjacking.

### Security headers example

```http
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
```

### IAM policy snippet

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::private-bucket/*"]
    }
  ]
}
```

## Step 5.1: Validation and testing

Controls are only real if you test them. Map each control to a verification step:

- Unit tests for input validation
- Integration tests for auth and access control
- Security scanning in CI for dependencies
- Periodic manual reviews for admin functionality

## Step 6: Prioritize

Use a simple risk score: impact x likelihood. Do not overthink the numbers; the point is to create a prioritized backlog.

| Risk | Impact | Likelihood | Score |
| --- | --- | --- | --- |
| Token theft via XSS | High | Medium | 12 |
| Admin API abuse | High | Low | 9 |
| Cache poisoning | Medium | Low | 6 |

## Step 7: Turn findings into work

Each threat should map to a task, an owner, and a test. Example backlog entries:

- Add rate limits to login and password reset endpoints.
- Record all admin actions in an append-only log.
- Encrypt backups and rotate encryption keys quarterly.

## Step 8: Review cadence

Threat models drift as systems evolve. Review whenever you:

- Add a new external integration
- Expose a new API surface
- Change authentication or authorization logic

A quarterly review is a good default for active products.

## Checklist

- [x] Draw a data flow diagram
- [x] List assets and trust boundaries
- [x] Apply STRIDE categories
- [ ] Map threats to controls
- [ ] Track controls in the backlog

## Further reading

- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [STRIDE paper](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
