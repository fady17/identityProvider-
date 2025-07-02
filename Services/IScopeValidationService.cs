// File: Orjnz.IdentityProvider.Web/Services/IScopeValidationService.cs
// using OpenIddict.EntityFrameworkCore.Models; // No longer needed if AppCustom is used
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System.Collections.Immutable;
using System.Threading; // For CancellationToken
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    public interface IScopeValidationService
    {
        /// <summary>
        /// Validates a list of requested scopes against system-defined scopes and client permissions.
        /// </summary>
        /// <param name="requestedScopes">The scopes being requested or consented to.</param>
        /// <param name="application">The client AppCustomOpenIddictApplication making the request.</param> // Changed type
        /// <param name="clientPermissions">The permissions already retrieved for the client application.</param>
        /// <param name="cancellationToken">The cancellation token.</param> // Added
        /// <returns>An immutable array of validated and permitted scope strings.</returns>
        Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
            ImmutableArray<string> requestedScopes,
            AppCustomOpenIddictApplication application, // Changed parameter type
            ImmutableArray<string> clientPermissions,
            CancellationToken cancellationToken = default); // Added CancellationToken

        /// <summary>
        /// Overload that fetches client permissions internally.
        /// </summary>
        /// <param name="requestedScopes">The scopes being requested.</param>
        /// <param name="application">The client AppCustomOpenIddictApplication.</param> // Changed type
        /// <param name="cancellationToken">The cancellation token.</param> // Added
        /// <returns>An immutable array of validated and permitted scope strings.</returns>
        Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
            ImmutableArray<string> requestedScopes,
            AppCustomOpenIddictApplication application, // Changed parameter type
            CancellationToken cancellationToken = default); // Added CancellationToken
    }
}
// // File: Orjnz.IdentityProvider.Web/Services/IScopeValidationService.cs
// using OpenIddict.EntityFrameworkCore.Models; // For OpenIddictEntityFrameworkCoreApplication
// using System.Collections.Immutable;
// using System.Threading.Tasks;

// namespace Orjnz.IdentityProvider.Web.Services
// {
//     public interface IScopeValidationService
//     {
//         /// <summary>
//         /// Validates a list of requested scopes against system-defined scopes and client permissions.
//         /// </summary>
//         /// <param name="requestedScopes">The scopes being requested or consented to.</param>
//         /// <param name="application">The client application making the request.</param>
//         /// <param name="clientPermissions">The permissions already retrieved for the client application.</param>
//         /// <returns>An immutable array of validated and permitted scope strings.</returns>
//         Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
//             ImmutableArray<string> requestedScopes,
//             OpenIddictEntityFrameworkCoreApplication application, // Pass the concrete application entity
//             ImmutableArray<string> clientPermissions); // Pass pre-fetched client permissions for efficiency

//         /// <summary>
//         /// Overload that fetches client permissions internally.
//         /// </summary>
//         Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
//             ImmutableArray<string> requestedScopes,
//             OpenIddictEntityFrameworkCoreApplication application);
//     }
// }