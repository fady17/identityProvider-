
# OpenIddict Identity Provider (Self-Hosted OIDC)

A minimal OpenID Connect provider built with **OpenIddict** and **.NET**, designed for learning and real-world testing.  
Supports standard auth flows and is tested with:

- 🔐 A custom **NextAuth.js** provider
- 📦 A protected **resource API**
- 🧪 Self-signed certificate and HTTPS configuration

---

## ✳️ Features

- Full OpenID Connect (OIDC) support using **OpenIddict**
- Authorization Code Flow with PKCE
- Custom client, scope, and resource definitions
- Tested with:
  - A Next.js + NextAuth frontend
  - A .NET resource API protected by access tokens
- Uses self-signed **X.509 certificate** for local HTTPS and signing

---

## 🧱 Stack

| Component       | Tech                          |
|-----------------|-------------------------------|
| OIDC Core       | OpenIddict (.NET)             |
| Certificate     | Self-signed (X.509)           |
| Client App      | Next.js + NextAuth.js         |
| Resource API    | .NET Minimal API              |

---

## 📦 Project Structure
/IdentityProvider        ← OpenIddict IdentityServer
/ResourceApi             ← Protected API https://github.com/fady17/ResourceApi.git
/Frontend                ← Next.js app using NextAuth (OIDC) https://github.com/fady17/Frontend-.git

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
dotnet run

🧪 Testing the Flow

✅ Frontend

Repo: (https://github.com/fady17/Frontend-.git)
	•	Uses NextAuth.js custom provider
	•	Supports login and session persistence
	•	Calls resource API using access tokens

✅ Resource API

Repo: https://github.com/fady17/ResourceApi.git
	•	Validates access tokens using the OpenIddict issuer
	•	Returns protected user or resource data

⸻

🔐 Scopes & Clients
	•	Client: nextjs-client
	•	Redirect URI: https://localhost:3000/api/auth/callback/openiddict
	•	Scopes: openid profile email api

Client + Scope configuration handled on startup via OpenIddict .

⸻

🧩 Notes
	•	If using PostgreSQL or MySQL, configure OpenIddict stores accordingly.
	•	All apps should be served over HTTPS (or insecureHttp=true only for dev).
	•	Self-signed certificates must be trusted by browser/system for redirects to work.
