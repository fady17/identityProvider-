using OpenIddict.Abstractions;
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;
using System.Collections.Immutable;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Defines the contract for a service responsible for constructing a user's <see cref="ClaimsIdentity"/>.
    /// This identity contains all the necessary claims, scopes, and resources (audiences) that will be
    /// embedded into the ID token and/or access token.
    /// </summary>
    public interface IClaimsGenerationService
    {
        /// <summary>
        /// Asynchronously builds a <see cref="ClaimsIdentity"/> for a given user, client application, and set of granted scopes.
        /// This method is responsible for populating the identity with standard OIDC claims, custom claims (like roles and provider_id),
        /// and setting the appropriate token destinations and audiences.
        /// </summary>
        /// <param name="user">The <see cref="ApplicationUser"/> for whom the identity is being created.</param>
        /// <param name="application">The client <see cref="AppCustomOpenIddictApplication"/> that initiated the request.</param>
        /// <param name="grantedScopes">The immutable array of scopes that the user has consented to for this request.</param>
        /// <param name="oidcRequest">The original <see cref="OpenIddictRequest"/> from the client, which may contain additional context.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains the fully constructed <see cref="ClaimsIdentity"/>,
        /// ready to be used by OpenIddict for token generation.
        /// </returns>
        Task<ClaimsIdentity> BuildUserClaimsIdentityAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application,
            ImmutableArray<string> grantedScopes,
            OpenIddictRequest oidcRequest,
            CancellationToken cancellationToken = default);
    }
}