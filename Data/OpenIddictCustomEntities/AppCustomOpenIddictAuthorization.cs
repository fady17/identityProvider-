// File: Orjnz.IdentityProvider.Web/Data/OpenIddictCustomEntities/AppCustomOpenIddictAuthorization.cs
using OpenIddict.EntityFrameworkCore.Models; // For OpenIddictEntityFrameworkCoreAuthorization
using System;

namespace Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities
{
    // TKey is string, TApplication and TToken are our custom types
    public class AppCustomOpenIddictAuthorization : OpenIddictEntityFrameworkCoreAuthorization<string, AppCustomOpenIddictApplication, AppCustomOpenIddictToken>
    {
        // Add custom properties here if needed for Authorizations in the future
    }
}