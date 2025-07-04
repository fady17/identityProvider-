using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Defines the contract for a service that manages the persistence of OpenIddict authorizations.
    /// This service provides an abstraction layer for creating or retrieving permanent user consents (authorizations)
    /// granted to client applications.
    /// </summary>
    public interface IAuthorizationPersistenceService
    {
        /// <summary>
        /// Ensures that a valid, permanent authorization exists for a given user, client application, and a specific set of scopes.
        /// If an existing authorization perfectly matches the criteria, it is returned. Otherwise, a new authorization is created and persisted.
        /// This method is idempotent and central to handling user consent.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> representing the user's identity. It must contain the claims for the scopes that have been granted.</param>
        /// <param name="user">The authenticated <see cref="ApplicationUser"/> for whom the authorization is being created.</param>
        /// <param name="application">The client <see cref="AppCustomOpenIddictApplication"/> to which the user is granting consent.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains the existing or newly created
        /// <see cref="AppCustomOpenIddictAuthorization"/>, or <c>null</c> if an error occurred (e.g., application not found).
        /// </returns>
        Task<AppCustomOpenIddictAuthorization?> EnsureAuthorizationAsync(
            ClaimsPrincipal principal,
            ApplicationUser user,
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the unique identifier for a given authorization entity.
        /// </summary>
        /// <param name="authorization">The <see cref="AppCustomOpenIddictAuthorization"/> entity whose ID is to be retrieved.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains the string representation
        /// of the authorization's unique identifier, or <c>null</c> if it cannot be determined.
        /// </returns>
        Task<string?> GetAuthorizationIdAsync(
            AppCustomOpenIddictAuthorization authorization,
            CancellationToken cancellationToken = default);
    }
}