# 🪪 Orjnz Identity Provider (v2)

A reusable, multi-tenant OpenID Connect Identity Provider built with **.NET**, **OpenIddict**, and **PostgreSQL** — designed to be used across multiple platforms with minimal configuration.

---

## ✨ Why This Exists

This identity provider is my attempt to **build once and reuse everywhere** — with support for:
- Adding OAuth providers via the Admin UI
- Issuing tenant-aware tokens
- Supporting external clients (e.g., Next.js, mobile apps)

---

## 🔧 Features

- ✅ OpenID Connect Identity Provider using **OpenIddict**
- ✅ Multi-tenant aware (via `provider_id` claim)
- ✅ Admin UI to manage:
  - Tenants (aka Providers)
  - Applications (OIDC Clients)
  - Users
- ✅ Works with `next-auth` or any OIDC-compliant client


# 🚀 Getting Started

## 📦 Requirements

- [.NET 9 SDK](https://dotnet.microsoft.com)
- PostgreSQL

## 🛠️ Run Locally

```bash
# Clone the repo
git clone https://github.com/fady17/identityProvider-.git
cd identityProvider-v2

# Setup your local PostgreSQL and update connection strings
dotnet ef migrations add OIDC

# Apply EF Core migrations
dotnet ef database update

# Run the Identity Provider
dotnet run 
```

## 🔑 Admin Credentials

Default credentials are seeded (configurable):
- **Email:** admin@orjnz.com
- **Password:** P@$$wOrd123!

✏️ You can change this in the `DataSeeder.cs` file or through the UI after login.

---

## 🔐 Security Status

⚠️ This project is currently in alpha and not hardened for production use. Please conduct your own security review before deploying in sensitive environments.

## TODO
ADD Docker Support

## 📜 License

This project is open source and available under the [MIT License](LICENSE).
