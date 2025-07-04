using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Defines the contract for a service that validates and filters OIDC scopes.
    /// This service ensures that any scopes granted to a client application are both defined in the system
    /// and explicitly permitted for that specific client.
    /// </summary>
    public interface IScopeValidationService
    {
        /// <summary>
        /// Asynchronously validates a list of requested scopes against a pre-fetched list of client permissions.
        /// This is the core validation logic that filters out any invalid or unpermitted scopes.
        /// </summary>
        /// <param name="requestedScopes">The list of scopes being requested by the client or consented to by the user.</param>
        /// <param name="application">The client application making the request.</param>
        /// <param name="clientPermissions">An array of permissions that have already been retrieved for the client application.</param>
        /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains an immutable array
        /// of scope strings that are valid and permitted for the client.
        /// </returns>
        Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
            ImmutableArray<string> requestedScopes,
            AppCustomOpenIddictApplication application,
            ImmutableArray<string> clientPermissions,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Asynchronously validates a list of requested scopes by first fetching the client's permissions internally.
        /// This overload provides a convenient way to perform validation without needing to retrieve permissions beforehand.
        /// </summary>
        /// <param name="requestedScopes">The list of scopes being requested by the client.</param>
        /// <param name="application">The client application making the request.</param>
        /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains an immutable array
        /// of scope strings that are valid and permitted for the client.
        /// </returns>
        Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
            ImmutableArray<string> requestedScopes,
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default);
    }
}