// File: Orjnz.IdentityProvider.Web/Data/OpenIddictCustomEntities/AppCustomOpenIddictToken.cs
using OpenIddict.EntityFrameworkCore.Models; // For OpenIddictEntityFrameworkCoreToken
using System;

namespace Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities
{
    // TKey is string, TApplication and TAuthorization are our custom types
    public class AppCustomOpenIddictToken : OpenIddictEntityFrameworkCoreToken<string, AppCustomOpenIddictApplication, AppCustomOpenIddictAuthorization>
    {
        // Add custom properties here if needed for Tokens in the future
    }
}