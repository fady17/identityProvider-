using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;
using System;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Defines the contract for a service that provides access to client application data.
    /// This service acts as a specialized interface over the OpenIddict application manager,
    /// ensuring that interactions consistently use the custom <see cref="AppCustomOpenIddictApplication"/> entity.
    /// </summary>
    public interface IClientApplicationService
    {
        /// <summary>
        /// Asynchronously retrieves a client application by its unique client identifier.
        /// </summary>
        /// <param name="clientId">The client ID of the application to find.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains the
        /// <see cref="AppCustomOpenIddictApplication"/> if found; otherwise, <c>null</c>.
        /// </returns>
        Task<AppCustomOpenIddictApplication?> GetApplicationByClientIdAsync(
            string clientId,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Asynchronously gets the unique database identifier (primary key) for a given application entity.
        /// </summary>
        /// <param name="application">The application entity.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains the string representation
        /// of the application's unique ID, or <c>null</c> if it cannot be determined.
        /// </returns>
        Task<string?> GetApplicationIdAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Asynchronously gets the consent type of the application (e.g., "explicit", "implicit", "systematic").
        /// This determines whether the user will be prompted for consent.
        /// </summary>
        /// <param name="application">The application entity.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains the consent type as a string.
        /// </returns>
        Task<string?> GetApplicationConsentTypeAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Asynchronously gets the permissions (e.g., allowed endpoints, grant types, scopes) granted to the application.
        /// </summary>
        /// <param name="application">The application entity.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains an immutable array of permission strings.
        /// </returns>
        Task<ImmutableArray<string>> GetClientPermissionsAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default);
        
        /// <summary>
        /// Synchronously retrieves the custom <see cref="Provider"/> identifier directly from the application entity.
        /// This provides a direct way to access the tenant/provider context of a client application.
        /// </summary>
        /// <param name="application">The application entity.</param>
        /// <returns>The <see cref="Guid"/> of the associated provider, or <c>null</c> if none is linked.</returns>
        Guid? GetProviderIdFromApplication(AppCustomOpenIddictApplication application);
    }
}