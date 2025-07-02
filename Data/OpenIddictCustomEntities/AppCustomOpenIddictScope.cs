// File: Orjnz.IdentityProvider.Web/Data/OpenIddictCustomEntities/AppCustomOpenIddictScope.cs
using OpenIddict.EntityFrameworkCore.Models; // For OpenIddictEntityFrameworkCoreScope
using System;

namespace Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities
{
    // TKey is string
    public class AppCustomOpenIddictScope : OpenIddictEntityFrameworkCoreScope<string>
    {
        // Add custom properties here if needed for Scopes in the future
        // e.g., public bool RequiresElevatedConsent { get; set; }
    }
}