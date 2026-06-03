# Security Policy — PhantomSignal // PHANTOM SIGNAL

---

## Supported Versions

Only the latest release on the `main` branch receives security fixes. Older tags are unsupported.

| Version | Supported |
|---------|-----------|
| Latest (`main`) | ✅ Active |
| Tagged releases | Patch-forward only |
| Forks / derivatives | Not our responsibility |

---

## Reporting a Vulnerability

**Do not open a public GitHub Issue for security vulnerabilities.**

If you discover a security flaw in PhantomSignal — including vulnerabilities in the web interface, plugin API, authentication handling, export pipeline, or dependency chain — report it privately:

**Email:** `security@phantomsignal.sh`  
**Subject line:** `[PhantomSignal SECURITY] <one-line description>`

### What to include

- A clear description of the vulnerability and the affected component
- Steps to reproduce, with the minimum configuration required
- The potential impact (what an attacker could achieve)
- Whether you have a proposed fix or patch
- Whether you intend to publish research on this issue, and if so, your preferred timeline

---

## Disclosure Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within 48 hours |
| Triage & severity assignment | Within 7 days |
| Fix developed | Within 30 days for critical; 60 days for others |
| Coordinated public disclosure | After fix is released |

If a fix requires longer than 60 days due to architectural complexity, we will communicate a revised timeline and provide mitigations where possible.

---

## Coordinated Disclosure

We follow coordinated (responsible) disclosure. That means:

- We will work with you to understand and fix the issue before anything is made public.
- We will credit you by name (or handle) in the release notes and security advisory, unless you prefer to remain anonymous.
- We ask that you do not publish or share details of the vulnerability until a fix has been released, or until we have mutually agreed on a disclosure date.

If we fail to respond within 48 hours or miss agreed milestones without communication, you are free to proceed with disclosure at your discretion after giving us reasonable final notice.

---

## Scope

The following are **in scope** for responsible disclosure:

- PhantomSignal web interface (Flask/SocketIO layer, authentication, session handling)
- Plugin/module API system
- Export pipeline (including encryption implementation)
- CLI input handling and command injection vectors
- Dependency vulnerabilities with a confirmed exploitation path

The following are **out of scope:**

- Vulnerabilities in third-party APIs that PhantomSignal integrates with (report those upstream)
- Issues that require physical access to the machine running PhantomSignal
- Theoretical attacks with no practical exploitation path
- Vulnerabilities in the user's own environment or misconfiguration

---

## Recognition

Researchers who report valid, in-scope vulnerabilities will be acknowledged in:

- The GitHub Security Advisory for the issue
- The release notes for the patching version

We do not currently offer a monetary bug bounty.

---

## A Note on the Nature of This Project

PhantomSignal is an OSINT and intelligence framework. If you discover that the tool can be used to gather intelligence on targets beyond its documented scope — that is by design for authorized use cases and is not a security vulnerability. Misuse of the tool is governed by the [Code of Conduct](CODE_OF_CONDUCT.md) and applicable law, not this policy.
