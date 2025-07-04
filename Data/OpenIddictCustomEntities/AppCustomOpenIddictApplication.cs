using OpenIddict.EntityFrameworkCore.Models;
using System;

namespace Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities
{
    /// <summary>
    /// Represents a custom OpenIddict application entity, extended with application-specific properties.
    /// This class allows associating an OIDC client application with a specific <see cref="Provider"/>.
    /// </summary>
    public class AppCustomOpenIddictApplication : OpenIddictEntityFrameworkCoreApplication<string, AppCustomOpenIddictAuthorization, AppCustomOpenIddictToken>
    {
        /// <summary>
        /// The foreign key to the <see cref="Provider"/> entity this application belongs to.
        /// This creates a tenant-like structure where each client application is owned by a provider.
        /// </summary>
        public Guid? ProviderId { get; set; }

        /// <summary>
        /// The navigation property to the associated <see cref="Provider"/>.
        /// </summary>
        public virtual Provider? Provider { get; set; }
    }
}