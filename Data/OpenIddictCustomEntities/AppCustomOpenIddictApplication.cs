// File: Orjnz.IdentityProvider.Web/Data/OpenIddictCustomEntities/AppCustomOpenIddictApplication.cs
using OpenIddict.EntityFrameworkCore.Models; // For OpenIddictEntityFrameworkCoreApplication
using System;

namespace Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities
{
    // TKey is string, TAuthorization and TToken will be our custom types
    public class AppCustomOpenIddictApplication : OpenIddictEntityFrameworkCoreApplication<string, AppCustomOpenIddictAuthorization, AppCustomOpenIddictToken>
    {
        // Custom properties
        public Guid? ProviderId { get; set; } // Nullable Foreign Key to your Provider entity

        // Navigation property to your Provider entity
        public virtual Provider? Provider { get; set; }

        // You can add other custom properties to the Application entity if needed in the future
        // public string? AnotherCustomProperty { get; set; }
    }
}