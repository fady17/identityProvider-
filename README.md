# Orjnz.IdentityProvider.Web - OpenID Connect Identity Provider

authentication and authorization server built on ASP.NET Core and OpenIddict. It serves as the central security authority for a distributed ecosystem of .NET Resource APIs and Next.js client applications.

The primary role of this IdP is to manage user identities, handle authentication flows, and issue secure tokens (JWTs) that client applications use to access protected resources. It is designed from the ground up with a multi-tenant architecture to support distinct provider organizations, each with their own users and client applications.

## 1. Project Overview

The Orjnz Identity Provider is the security foundation of our service-oriented architecture. It is a standalone ASP.NET Core application responsible for:

- **Centralized User Authentication:** Providing a single, consistent login experience for all users across multiple applications.
- **OpenID Connect & OAuth 2.0 Compliance:** Implementing standard protocols for identity and access control, ensuring broad compatibility and security best practices.
- **Issuing Security Tokens:** Generating signed `id_token` and `access_token` JWTs that contain user identity information and permissions (scopes).
- **Multi-Tenant Support:** Natively supporting a multi-provider (tenant) model where users and client applications can be associated with specific organizations.
- **Administrative Interface:** Offering a secure admin area for managing users, client applications, scopes, and providers.

By centralizing these concerns, the IdP allows downstream services and clients to focus on their core business logic, delegating complex authentication and identity management to this specialized service.

## 2. Architecture

The IdP is built using a modern, service-oriented approach that emphasizes flexibility and maintainability.

### Core Components

- **ASP.NET Core 7:** The underlying web framework providing a high-performance, cross-platform foundation.
- **OpenIddict 5.x:** A powerful, low-level OpenID Connect server library that offers deep customization capabilities. We chose OpenIddict over more opinionated frameworks to enable a bespoke multi-tenant security model.
- **ASP.NET Core Identity:** Used for core user and role management (storage, password hashing, etc.), extended with custom user and role entities.
- **Entity Framework Core with PostgreSQL:** Provides the data persistence layer for all user, application, scope, and token data.
- **Serilog:** Implemented for structured, production-ready logging.

### Key Architectural Patterns

- **Custom Identity & OpenIddict Entities:** The system extends the base ASP.NET Identity and OpenIddict models.
  - `ApplicationUser`: Our custom user class includes a `DefaultProviderId`, linking a user to a tenant.
  - `Provider`: A custom entity representing a tenant organization.
  - `AppCustomOpenIddictApplication`: Our custom OIDC application class includes a nullable `ProviderId` foreign key, directly linking a client application to its owning tenant.
- **Service-Oriented Design:** Core logic is decoupled into specialized services, promoting separation of concerns and testability. Key services include:
  - `IClaimsGenerationService`: Dynamically constructs claims for tokens, including the critical `provider_id` claim based on application and user context.
  - `IConsentService`: Manages the logic for the user consent screen, handling different consent types (implicit, explicit, etc.).
  - `IUserAuthenticationService`: A facade that simplifies interactions with ASP.NET Core Identity during the OIDC flow.
- **Custom Event Handlers:** We leverage OpenIddict's event-based model to inject custom logic, such as using a custom `UserInfoHandler` to control the data returned from the `/connect/userinfo` endpoint.

## 3. Security Features

This Identity Provider implements a robust set of security features to protect user data and control access to the ecosystem.

### Supported Flows & Features

- **Authorization Code Flow with PKCE:** The primary and most secure flow for both server-side web apps (confidential clients) and public clients like SPAs (Next.js) and mobile apps. PKCE (Proof Key for Code Exchange) is enforced for public clients to mitigate authorization code interception attacks.
- **Client Credentials Flow:** Used for secure, direct machine-to-machine communication between backend services.
- **Refresh Token Flow:** Allows applications to obtain new access tokens without requiring the user to re-authenticate, providing a seamless user experience for long-lived sessions.
- **Device Authorization Flow:** Supported for input-constrained devices that cannot host a browser.
- **OIDC End-Session Endpoint:** Implements proper federated logout, ensuring users are signed out of both the IdP and client applications.

### Token & Certificate Management

- **Signed JWTs:** All access tokens and ID tokens are digitally signed using a secure X.509 certificate, allowing resource servers to verify their authenticity and integrity.
- **Configuration-Driven Certificates:** The IdP is configured to load signing and encryption certificates from a PFX file specified in `appsettings.json`, allowing for easy management in different environments (development vs. production).
- **Token Claim Destinations:** Claim destinations are carefully configured to ensure that sensitive or unnecessary information is not leaked into the wrong token (e.g., identity-specific claims are correctly placed in the `id_token`, while API-specific claims are in the `access_token`).

## 4. Database Schema

The database schema is managed by Entity Framework Core and is composed of three main parts:

- **ASP.NET Core Identity Tables:** Standard tables like `AspNetUsers`, `AspNetRoles`, `AspNetUserRoles`, etc., using our custom `ApplicationUser` and `ApplicationRole` entities. The `ApplicationUser` table includes the `DefaultProviderId` column.
- **Custom `Providers` Table:** A dedicated table to store tenant information (ID, Name, ShortCode, etc.). This is central to our multi-tenancy model.
- **OpenIddict Tables:**
  - `OpenIddictApplications`: Stores client application registrations. Our custom `AppCustomOpenIddictApplication` adds a `ProviderId` column to this table, creating a direct foreign key relationship to the `Providers` table.
  - `OpenIddictScopes`: Defines all available scopes (permissions).
  - `OpenIddictAuthorizations`: Stores permanent user consent grants.
  - `OpenIddictTokens`: Persists reference tokens, refresh tokens, and device codes.

This schema design tightly integrates the concept of a "Provider" or "Tenant" into the core security entities of the system.


## 5. API Endpoints

This Identity Provider exposes standard OpenID Connect endpoints for discovery, authentication, and token management.

-   **Discovery Endpoint:** `/.well-known/openid-configuration`
    -   **Method:** `GET`
    -   **Description:** A metadata endpoint that allows clients and APIs to automatically discover other endpoint URLs, supported scopes, claims, and public signing keys.

-   **Authorization Endpoint:** `/connect/authorize`
    -   **Method:** `GET`
    -   **Description:** The entry point for all user-facing authentication flows. Client applications redirect the user's browser here to initiate sign-in and consent.

-   **Token Endpoint:** `/connect/token`
    -   **Method:** `POST`
    -   **Description:** A backend channel where client applications exchange authorization codes or refresh tokens for new access tokens.

-   **UserInfo Endpoint:** `/connect/userinfo`
    -   **Method:** `GET`/`POST`
    -   **Description:** A protected endpoint that returns claims about the authenticated user. It requires a valid access token.

-   **End Session (Logout) Endpoint:** `/connect/logout`
    -   **Method:** `GET`/`POST`
    -   **Description:** Terminates the user's session at the IdP and facilitates federated logout by redirecting back to the client application.

## 6. Development Setup & Deployment

This section outlines the steps required to run the Identity Provider locally and provides considerations for a production deployment.

### Local Development Setup

1.  **Prerequisites:**
    -   .NET SDK
    -   PostgreSQL Database (or configure `appsettings.json` for a different provider like SQL Server or SQLite).

2.  **Configuration:**
    -   Clone the repository.
    -   In `appsettings.Development.json`, configure the `DefaultConnection` connection string for your local database.
    -   Ensure the `OpenIddictSeedData` section is configured with your desired initial admin users, clients, and scopes for testing.
    -   Configure the path and password for the Kestrel and OpenIddict PFX certificates under the `Kestrel:Certificates:Default` and `OpenIddict:Certificates` sections. For initial development, the fallback to ASP.NET Core development certificates can be used if no PFX is provided.

3.  **Database Migration:**
    -   Run Entity Framework Core migrations to create the database schema:
        ```bash
        dotnet ef database update
        ```

4.  **Execution:**
    -   Run the project from your IDE or using the .NET CLI:
        ```bash
        dotnet run
        ```
    -   The application will start, and on its first run, the `DataSeeder` will populate the database with the configured seed data. The IdP will be available at the URL specified in `launchSettings.json` (e.g., `https://localhost:7066`).

### Production Deployment (Considerations)

-   **Certificate Management:** In production, do not use development certificates. Use a trusted X.509 certificate for both Kestrel (HTTPS) and OpenIddict (token signing). Store these securely, for example, using Azure Key Vault, AWS Secrets Manager, or the host's certificate store.
-   **Database:** Use a production-grade PostgreSQL instance. Ensure connection strings are managed securely via environment variables or a configuration service, not checked into source control.
-   **Secrets Management:** All secrets (database passwords, PFX passwords, etc.) must be managed outside of `appsettings.json`. Use tools like Azure Key Vault, User Secrets (for dev), or environment variables.
-   **Hosting:** Host the application on a reliable platform like Azure App Service, AWS, or a container orchestration system like Kubernetes. Ensure HTTPS is enforced.
-   **Logging:** Configure Serilog to write to a persistent, searchable sink like Seq, Application Insights, or Elasticsearch for effective monitoring and diagnostics.

---

🧪 Testing the Flow

✅ Frontend

Repo: (https://github.com/fady17/Frontend-.git)


✅ Resource API

Repo: https://github.com/fady17/ResourceApi.git

⸻



⸻

## 7. Integration Guide

This Identity Provider (IdP) is designed to be the central authentication authority for a variety of applications. This guide provides instructions on how to integrate two common types of applications: a backend Resource API and a frontend Single-Page Application (SPA).

### A. Integrating a .NET Resource API

A Resource API is a backend service that protects its endpoints and relies on this IdP to validate access tokens. Here is how to configure a .NET Minimal API to trust tokens issued by this IdP.

**1. Project Configuration (`Program.cs`)**

In your Resource API's `Program.cs`, you need to configure the OpenIddict validation handler.

```csharp
// File: YourResourceApi/Program.cs

using OpenIddict.Validation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// 1. Add Authentication services and set the default scheme to OpenIddict Validation.
builder.Services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);

// 2. Add the OpenIddict validation services.
builder.Services.AddOpenIddict()
    .AddValidation(options =>
    {
        // 3. Configure the issuer URL.
        // This MUST exactly match the public-facing URL of this Identity Provider.
        // It's used to validate the 'iss' claim in the JWT.
        options.SetIssuer("https://localhost:7066/"); 

        // 4. Configure the audience.
        // The API will only accept tokens that contain this audience string in their 'aud' claim.
        // This ensures a token for one API cannot be used to access another.
        // This value must be one of the resources associated with a scope in the IdP.
        options.AddAudiences("testclinic-api");

        // 5. Configure ASP.NET Core and HTTP client integration.
        // This allows OpenIddict to automatically discover the IdP's configuration and
        // public keys from its `.well-known/openid-configuration` endpoint.
        options.UseAspNetCore();
        options.UseSystemNetHttp();
    });

// Add other necessary services like Authorization.
builder.Services.AddAuthorization();

var app = builder.Build();

// ... configure pipeline ...

// Ensure Authentication and Authorization middleware are added to the pipeline.
app.UseAuthentication();
app.UseAuthorization();

// Protect your endpoints.
app.MapGet("/api/secure-data", () => "This is protected data.")
   .RequireAuthorization(); // Use this for Minimal APIs.

app.Run();
```

**2. App Settings (`appsettings.json`)**

While the values can be hardcoded as above, it's best practice to configure them in `appsettings.json`.

```json
{
  "OpenIddict": {
    "Validation": {
      "Issuer": "https://localhost:7066/"
    }
  }
}
```

The `AddAudiences` value (`testclinic-api`) is specific to the API's identity and is typically kept in code.

With this configuration, any endpoint marked with `[Authorize]` or `.RequireAuthorization()` will automatically validate the `Authorization: Bearer <token>` header against this IdP.

### B. Integrating a Next.js Client Application

A frontend client application handles the user-facing part of the authentication flow. We recommend using the `next-auth` library for its robust handling of OIDC flows.

**1. Environment Configuration (`.env.local`)**

Create a `.env.local` file in your Next.js project root:

```bash
# The public-facing URL of this Identity Provider.
OIDC_ISSUER="https://localhost:7066"

# The Client ID for this Next.js app, as registered in the IdP admin area.
OIDC_CLIENT_ID="nextjs-client-app"

# For public clients using PKCE, the client secret MUST be empty.
OIDC_CLIENT_SECRET=

# A secret used by NextAuth.js to sign its own session cookies.
# Generate with: openssl rand -base64 32
NEXTAUTH_SECRET="your-unique-nextauth-secret"

# The canonical URL of the Next.js application.
NEXTAUTH_URL="http://localhost:3000"
```

**2. NextAuth.js Configuration (`app/api/auth/[...nextauth]/route.ts`)**

Configure `next-auth` to use our IdP as a generic OIDC provider.

```typescript
// File: /app/api/auth/[...nextauth]/route.ts

import NextAuth, { NextAuthOptions } from "next-auth";

export const authOptions: NextAuthOptions = {
  providers: [
    {
      id: "oidc", // A unique identifier for this provider.
      name: "My Custom IDP", // Display name for the sign-in button.
      type: "oauth",
      wellKnown: `${process.env.OIDC_ISSUER}/.well-known/openid-configuration`,
      clientId: process.env.OIDC_CLIENT_ID,
      clientSecret: process.env.OIDC_CLIENT_SECRET, // Will be empty for public client
      authorization: {
        params: {
          // 'offline_access' is required to get a refresh token.
          scope: "openid profile email offline_access testclinic-api",
        },
      },
      checks: ["pkce", "state"], // Enforce PKCE for security.
      idToken: true,

      // This callback maps claims from the IdP to the NextAuth user session.
      async profile(profile) {
        return {
          id: profile.sub,
          name: profile.name,
          email: profile.email,
          // Map our custom tenant claim
          providerId: profile.provider_id, 
        };
      },
    },
  ],
  callbacks: {
    // Implement the 'jwt' and 'session' callbacks to handle token refresh
    // and expose the access token to the client. See the client application's
    // documentation for a full example.
  },
  secret: process.env.NEXTAUTH_SECRET,
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
```

**3. Using the Session in a Component**

In your React components, you can then use the `useSession` hook to access user data and the `signIn`/`signOut` functions. The `accessToken` required by the Resource API is available on the `session` object.

```jsx
// File: MyComponent.tsx

"use client";
import { useSession, signIn } from "next-auth/react";

export default function MyComponent() {
  const { data: session, status } = useSession();

  if (status === "authenticated") {
    // The access token is ready to be sent to a Resource API.
    const accessToken = session.accessToken; 
    console.log("Token:", accessToken);

    return <p>Signed in as {session.user?.name}</p>;
  }

  return <button onClick={() => signIn("oidc")}>Sign In</button>;
}
```

## 8. Troubleshooting


-   **401 Unauthorized from Resource API:**
    -   Verify the `Issuer` URL in the API's configuration exactly matches the public URL of this IdP.
    -   Check that the `Audience` in the API's configuration matches the resource name associated with the requested scope.
    -   Ensure the system clocks on the IdP server and API server are synchronized.

-   **`invalid_client` error during login:**
    -   Confirm the `client_id` used by the client application exactly matches a registered application in the IdP.
    -   Ensure the `RedirectUri` sent by the client is one of the exact URIs registered for that application in the IdP.

-   **Token Refresh Fails:**
    -   Make sure the client requested the `offline_access` scope during the initial login to receive a refresh token.
    -   Ensure the client's permissions in the IdP include the `refresh_token` grant type (`gtn:refresh_token`).


---