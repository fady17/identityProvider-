// File: Orjnz.IdentityProvider.Web/Services/AuthorizationPersistenceService.cs
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
// using OpenIddict.EntityFrameworkCore.Models; // No longer directly needed
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustom types
using System;
// using System.Collections.Generic; // Not strictly needed anymore if only dealing with one auth
// using System.Collections.Immutable; // Not used here
using System.Linq; // For .Any() if used with List<object>
using System.Security.Claims;
// using System.Text.Json; // Not used here
using System.Threading; // For CancellationToken
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Orjnz.IdentityProvider.Web.Services
{
    public class AuthorizationPersistenceService : IAuthorizationPersistenceService
    {
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictApplicationManager _applicationManager; // Still needed for GetIdAsync on application
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<AuthorizationPersistenceService> _logger;

        public AuthorizationPersistenceService(
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictApplicationManager applicationManager,
            UserManager<ApplicationUser> userManager,
            ILogger<AuthorizationPersistenceService> logger)
        {
            _authorizationManager = authorizationManager ?? throw new ArgumentNullException(nameof(authorizationManager));
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<AppCustomOpenIddictAuthorization?> EnsureAuthorizationAsync( // Changed return type
            ClaimsPrincipal principal,
            ApplicationUser user,
            AppCustomOpenIddictApplication application, // Changed parameter type
            CancellationToken cancellationToken = default) // Added CancellationToken
        {
            ArgumentNullException.ThrowIfNull(principal);
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(application);

            string userId = await _userManager.GetUserIdAsync(user); // Does not take CT
            // GetIdAsync on manager can take the custom app type and CT
            string? applicationId = await _applicationManager.GetIdAsync(application, cancellationToken);

            if (string.IsNullOrEmpty(applicationId))
            {
                var clientIdForError = await _applicationManager.GetClientIdAsync(application, cancellationToken);
                _logger.LogError("Could not retrieve ID for application {ClientIdentifier}", clientIdForError ?? "UNKNOWN_CLIENT");
                return null;
            }

            var principalScopes = principal.GetScopes();

            AppCustomOpenIddictAuthorization? existingMatchingAuthorization = null;
            // IOpenIddictAuthorizationManager.FindAsync returns IAsyncEnumerable<object>
            await foreach (var authObject in _authorizationManager.FindAsync(
                subject: userId,
                client: applicationId,
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: principalScopes,
                cancellationToken: cancellationToken
            ).WithCancellation(cancellationToken))
            {
                // The actual object returned by FindAsync will be AppCustomOpenIddictAuthorization
                // because of ReplaceDefaultEntities.
                if (authObject is AppCustomOpenIddictAuthorization concreteAuth)
                {
                    existingMatchingAuthorization = concreteAuth;
                    break;
                }
                else if (authObject != null) // Log if it's something unexpected
                {
                     _logger.LogWarning("Found authorization object of unexpected type {ActualType} during FindAsync. Expected {ExpectedType}.",
                        authObject.GetType().FullName, typeof(AppCustomOpenIddictAuthorization).FullName);
                }
            }

            if (existingMatchingAuthorization != null)
            {
                var authId = await _authorizationManager.GetIdAsync(existingMatchingAuthorization, cancellationToken);
                _logger.LogInformation(
                    "Found existing permanent authorization {AuthorizationId} with matching scopes for user {UserId}, client {ClientId}.",
                    authId, userId, applicationId);
                return existingMatchingAuthorization;
            }

            _logger.LogInformation(
                "No existing permanent authorization found with exact scope match for current grant. Creating new authorization for user {UserId}, client {ClientId} with scopes [{Scopes}].",
                userId, applicationId, string.Join(", ", principalScopes));

            // CreateAsync takes the principal, subject, client (applicationId), type, and scopes.
            // It will internally create an instance of AppCustomOpenIddictAuthorization.
            var newAuthorizationObject = await _authorizationManager.CreateAsync(
                principal: principal,
                subject: userId,
                client: applicationId,
                type: AuthorizationTypes.Permanent,
                scopes: principalScopes,
                cancellationToken: cancellationToken
            );

            // Cast the result to our custom type.
            if (newAuthorizationObject is AppCustomOpenIddictAuthorization concreteNewAuth)
            {
                var newAuthId = await _authorizationManager.GetIdAsync(concreteNewAuth, cancellationToken);
                _logger.LogInformation("Successfully created new authorization {NewAuthId}", newAuthId);
                return concreteNewAuth;
            }
            
            _logger.LogError(
                "Failed to create new authorization or the created object was not of type {ExpectedType} for user {UserId}, client {ClientId}. Actual type: {ActualType}",
                typeof(AppCustomOpenIddictAuthorization).FullName, userId, applicationId, newAuthorizationObject?.GetType().FullName);
            return null;
        }

        public async Task<string?> GetAuthorizationIdAsync(
            AppCustomOpenIddictAuthorization authorization, // Changed parameter type
            CancellationToken cancellationToken = default) // Added CancellationToken
        {
            ArgumentNullException.ThrowIfNull(authorization);
            // Pass CancellationToken to the manager method
            return await _authorizationManager.GetIdAsync(authorization, cancellationToken);
        }
    }
}
// // File: Orjnz.IdentityProvider.Web/Services/AuthorizationPersistenceService.cs
// using Microsoft.AspNetCore.Identity;
// using Microsoft.Extensions.Logging;
// using OpenIddict.Abstractions;
// using OpenIddict.EntityFrameworkCore.Models; // For OpenIddictEntityFrameworkCoreAuthorization etc.
// using Orjnz.IdentityProvider.Web.Data;
// using System;
// using System.Collections.Generic; // For List<T>
// using System.Collections.Immutable; // For ImmutableArray<string>
// using System.Linq; // For Any()
// using System.Security.Claims;
// using System.Text.Json; // For JsonSerializer
// using System.Threading.Tasks;
// using static OpenIddict.Abstractions.OpenIddictConstants;

// namespace Orjnz.IdentityProvider.Web.Services
// {
//     public class AuthorizationPersistenceService : IAuthorizationPersistenceService
//     {
//         private readonly IOpenIddictAuthorizationManager _authorizationManager;
//         private readonly IOpenIddictApplicationManager _applicationManager;
//         private readonly UserManager<ApplicationUser> _userManager;
//         private readonly ILogger<AuthorizationPersistenceService> _logger;

//         public AuthorizationPersistenceService(
//             IOpenIddictAuthorizationManager authorizationManager,
//             IOpenIddictApplicationManager applicationManager,
//             UserManager<ApplicationUser> userManager,
//             ILogger<AuthorizationPersistenceService> logger)
//         {
//             _authorizationManager = authorizationManager ?? throw new ArgumentNullException(nameof(authorizationManager));
//             _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
//             _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
//             _logger = logger ?? throw new ArgumentNullException(nameof(logger));
//         }

//         public async Task<OpenIddictEntityFrameworkCoreAuthorization?> EnsureAuthorizationAsync(
//             ClaimsPrincipal principal, // The fully built principal for the CURRENT request
//             ApplicationUser user,
//             OpenIddictEntityFrameworkCoreApplication application)
//         {
//             ArgumentNullException.ThrowIfNull(principal);
//             ArgumentNullException.ThrowIfNull(user);
//             ArgumentNullException.ThrowIfNull(application);

//             string userId = await _userManager.GetUserIdAsync(user);
//             string? applicationId = await _applicationManager.GetIdAsync(application);

//             if (string.IsNullOrEmpty(applicationId))
//             {
//                 _logger.LogError("Could not retrieve ID for application {ClientIdentifier}", await _applicationManager.GetClientIdAsync(application));
//                 return null;
//             }

//             var principalScopes = principal.GetScopes(); // Scopes from the current grant/principal

//             // Attempt to find an existing PERMANENT authorization that already grants ALL of these exact scopes.
//             // The `scopes` parameter in `FindAsync` acts as a filter.
//             OpenIddictEntityFrameworkCoreAuthorization? existingMatchingAuthorization = null;
//             await foreach (var authObject in _authorizationManager.FindAsync(
//                 subject: userId,
//                 client: applicationId,
//                 status: Statuses.Valid,
//                 type: AuthorizationTypes.Permanent,
//                 scopes: principalScopes // Pass the exact scopes from the current principal
//             ))
//             {
//                 if (authObject is OpenIddictEntityFrameworkCoreAuthorization concreteAuth)
//                 {
//                     // FindAsync with scopes should return only those matching all specified scopes.
//                     // We can take the first one found (or LastOrDefault as in Balosar).
//                     existingMatchingAuthorization = concreteAuth;
//                     break; // Found a match
//                 }
//             }

//             if (existingMatchingAuthorization != null)
//             {
//                 _logger.LogInformation(
//                     "Found existing permanent authorization {AuthorizationId} with matching scopes for user {UserId}, client {ClientId}.",
//                     await _authorizationManager.GetIdAsync(existingMatchingAuthorization), userId, applicationId);

//                 // IMPORTANT: While scopes match, the *resources* associated with an old authorization aren't easily compared
//                 // without looking at tokens issued under it. OpenIddict's token issuance will use the resources
//                 // currently set on the 'principal' being signed in.
//                 // If the resources associated with these scopes have changed system-wide, the new token will reflect that.
//                 // Reusing this authorization primarily prevents re-consent for the same scopes and allows refresh token reuse.
//                 // For stricter resource matching on reuse, more complex logic involving token introspection or
//                 // custom properties on the authorization would be needed.
//                 // The Balosar sample implicitly handles this by forming a new identity based on current request
//                 // and linking it to an existing or new authorization.

//                 return existingMatchingAuthorization;
//             }

//             _logger.LogInformation(
//                 "No existing permanent authorization found with exact scope match for current grant. Creating new authorization for user {UserId}, client {ClientId} with scopes [{Scopes}].",
//                 userId, applicationId, string.Join(", ", principalScopes));

//             // Create a new authorization.
//             // Use the overload that takes the principal AND the scopes explicitly.
//             // The principal is used for properties, subject, client. Scopes are set on the authorization.
//             // Resources for the token will come from what's set on the principal.Identity.SetResources().
//             var newAuthorizationObject = await _authorizationManager.CreateAsync(
//                 principal: principal,       // The ClaimsPrincipal containing the identity with all claims, scopes, resources, destinations
//                 subject: userId,
//                 client: applicationId,
//                 type: AuthorizationTypes.Permanent,
//                 scopes: principalScopes      // Explicitly pass the scopes for the new authorization record
//             );

//             if (newAuthorizationObject is OpenIddictEntityFrameworkCoreAuthorization concreteNewAuth)
//             {
//                 _logger.LogInformation("Successfully created new authorization {NewAuthId}", await _authorizationManager.GetIdAsync(concreteNewAuth));
//                 return concreteNewAuth;
//             }

//             _logger.LogError(
//                 "Failed to create or cast new authorization to OpenIddictEntityFrameworkCoreAuthorization for user {UserId}, client {ClientId}.",
//                 userId, applicationId);
//             return null;
//         }

//         public async Task<string?> GetAuthorizationIdAsync(OpenIddictEntityFrameworkCoreAuthorization authorization)
//         {
//             ArgumentNullException.ThrowIfNull(authorization);
//             return await _authorizationManager.GetIdAsync(authorization);
//         }
//     }
// }