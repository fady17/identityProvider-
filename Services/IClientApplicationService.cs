// File: Orjnz.IdentityProvider.Web/Services/IClientApplicationService.cs
// using OpenIddict.EntityFrameworkCore.Models; // Not strictly needed if AppCustomOpenIddictApplication is used consistently
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System;
using System.Collections.Immutable;
// using System.Text.Json; // No longer needed if GetProviderIdFromApplicationPropertiesAsync is removed
using System.Threading; // For CancellationToken
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    public interface IClientApplicationService
    {
        Task<AppCustomOpenIddictApplication?> GetApplicationByClientIdAsync(
            string clientId,
            CancellationToken cancellationToken = default); // Added CancellationToken

        Task<string?> GetApplicationIdAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default); // Added CancellationToken

        Task<string?> GetApplicationConsentTypeAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default); // Added CancellationToken

        Task<ImmutableArray<string>> GetClientPermissionsAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default); // Added CancellationToken
        
        // This method directly accesses the property, so it's synchronous and doesn't need CancellationToken.
        Guid? GetProviderIdFromApplication(AppCustomOpenIddictApplication application);
    }
}