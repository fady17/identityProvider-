# From Foundation to Framework: Evolving a .NET Identity System for Multi-Tenant SaaS

**Author:** Fady  
**Last Updated:** July 2025

---

## Overview

This case study documents the evolution of the Orjnz Identity Provider — a custom, OpenID Connect-compliant system built to support identity-driven, multi-tenant applications. What began as a specific solution to a real-world SaaS requirement gradually transformed into a reusable framework with its own admin panel, token pipeline, and strategic architecture.

---

## Why Move from Duende IdentityServer to OpenIddict?

The original identity implementation used Duende IdentityServer. It worked well for standard OpenID Connect flows but wasn’t flexible enough for what came next: a requirement to tightly couple OIDC clients with specific tenant (provider) entities and inject custom claims based on that relationship.

Duende would’ve required extensive customization of internal services and entity models. Instead of fighting the tool, I chose OpenIddict, which gave me more room to think in terms of architecture rather than patches.

The goal wasn’t just to solve a one-off problem — it was to **build a foundation** I could reuse across projects, with the potential to:
- Add new tenants (providers) dynamically via an Admin UI
- Issue tenant-scoped access tokens with minimal friction
- Even expose the system as a standalone SaaS auth layer — someday

The move to OpenIddict wasn’t about "what's better." It was about choosing the tool that gave me permission to over-engineer responsibly — and possibly benefit from it in the long run.

---

## Lessons Learned

### 1. Building a Generic Identity Layer Is Surprisingly Hard
Even with full control over the data models and token pipeline, turning those knobs safely takes time. Every field, claim, and relationship becomes a potential point of confusion later.

### 2. Token Design Deserves as Much Thought as Schema Design
Embedding a `provider_id` claim into every access token feels simple in hindsight, but designing the mechanics around when and how it's injected — and making it authoritative — was a surprisingly non-trivial process.

### 3. Reusability Emerges from Pain, Not Planning
This wasn’t built as a product — it emerged from pain. Once the third or fourth similar project came up, the value of having a consistent identity backbone became obvious. If I had tried to "design the perfect system" from the start, I would've failed. It had to grow out of constraints.

---

## Next Steps / Future Considerations

The foundation is now strong. Here’s where it could go next:

### ✅ Short-Term
- Polish and expand the Admin UI (e.g., show issued tokens, support app secrets).
- Improve documentation for onboarding and extensibility.
- Add a hosted demo or walkthrough for GitHub visitors.

### 🧱 Mid-Term
- Add support for per-provider roles and scopes.
- Introduce rate limiting or access logging at the token level.
- Create a template project that consumes the IdP as a reusable service.

### 🌍 Long-Term (Aspirational)
- Offer this as a managed authentication layer for SaaS products.
- Enable provider-specific branding (login page themes, email templates).
- Create plugins for external directory integrations (e.g., LDAP, Azure AD B2C).

---

## Final Thoughts

This identity layer may have started from a requirement, but it turned into a platform. Whether I use it in 2 projects or 20, the cost of doing it "right" once has already paid off.

And who knows — maybe it becomes the start of something much bigger. For now, it solves a hard problem, cleanly. That’s enough.

---