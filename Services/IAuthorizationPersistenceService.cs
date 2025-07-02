// File: Orjnz.IdentityProvider.Web/Services/IAuthorizationPersistenceService.cs
// using OpenIddict.EntityFrameworkCore.Models; // No longer directly needed for these specific types in interface
using Orjnz.IdentityProvider.Web.Data; // For ApplicationUser
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustom types
using System.Security.Claims; // For ClaimsPrincipal
using System.Threading; // For CancellationToken
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    public interface IAuthorizationPersistenceService
    {
        /// <summary>
        /// Ensures that a valid permanent authorization exists for the given user, client, and the
        /// scopes/resources present in the principal. If one exists that matches, it's returned.
        /// Otherwise, a new one is created.
        /// </summary>
        /// <param name="principal">The ClaimsPrincipal representing the user's identity,
        /// with granted scopes and resources already set.</param>
        /// <param name="user">The authenticated ApplicationUser.</param>
        /// <param name="application">The client AppCustomOpenIddictApplication.</param> // Changed type
        /// <param name="cancellationToken">The cancellation token.</param> // Added
        /// <returns>The existing or newly created AppCustomOpenIddictAuthorization.</returns> // Changed type
        Task<AppCustomOpenIddictAuthorization?> EnsureAuthorizationAsync( // Changed return type
            ClaimsPrincipal principal,
            ApplicationUser user,
            AppCustomOpenIddictApplication application, // Changed parameter type
            CancellationToken cancellationToken = default); // Added CancellationToken

        /// <summary>
        /// Gets the string identifier of the given authorization entity.
        /// </summary>
        /// <param name="authorization">The AppCustomOpenIddictAuthorization entity.</param> // Changed type
        /// <param name="cancellationToken">The cancellation token.</param> // Added
        /// <returns>The string ID of the authorization.</returns>
        Task<string?> GetAuthorizationIdAsync(
            AppCustomOpenIddictAuthorization authorization, // Changed parameter type
            CancellationToken cancellationToken = default); // Added CancellationToken
    }
}