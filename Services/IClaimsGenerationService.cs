
// File: Orjnz.IdentityProvider.Web/Services/IClaimsGenerationService.cs
using OpenIddict.Abstractions;
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;
using System.Collections.Immutable;
using System.Security.Claims;
using System.Threading; // For CancellationToken
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    public interface IClaimsGenerationService
    {
        Task<ClaimsIdentity> BuildUserClaimsIdentityAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application,
            ImmutableArray<string> grantedScopes,
            OpenIddictRequest oidcRequest, // oidcRequest has a CancellationToken property
            CancellationToken cancellationToken = default); // Add an optional CancellationToken parameter
    }
}
// // File: Orjnz.IdentityProvider.Web/Services/IClaimsGenerationService.cs
// using OpenIddict.Abstractions; // For OpenIddictRequest
// using OpenIddict.EntityFrameworkCore.Models; // For OpenIddictEntityFrameworkCoreApplication
// using Orjnz.IdentityProvider.Web.Data; // For ApplicationUser
// using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;
// using System.Collections.Immutable;
// using System.Security.Claims;
// using System.Threading.Tasks;

// namespace Orjnz.IdentityProvider.Web.Services
// {
//     public interface IClaimsGenerationService
//     {
//         /// <summary>
//         /// Builds a ClaimsIdentity for OpenIddict based on the authenticated user, client, granted scopes, and OIDC request.
//         /// </summary>
//         /// <param name="user">The authenticated application user.</param>
//         /// <param name="application">The client application requesting authorization.</param>
//         /// <param name="grantedScopes">The final list of scopes granted to the client for this request.</param>
//         /// <param name="oidcRequest">The original OpenID Connect request from the client.</param>
//         /// <returns>A configured ClaimsIdentity ready for OpenIddict processing.</returns>
//         Task<ClaimsIdentity> BuildUserClaimsIdentityAsync(
//             ApplicationUser user,
//              AppCustomOpenIddictApplication application,
//             // OpenIddictEntityFrameworkCoreApplication application,
//             ImmutableArray<string> grantedScopes,
//             OpenIddictRequest oidcRequest); // Pass oidcRequest for context like nonce, response_type if needed for claims
//             CancellationToken cancellationToken = default);
//     }

// }