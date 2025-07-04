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
    /// <summary>
    /// Provides the concrete implementation for managing the persistence of OpenIddict authorizations.
    /// This service orchestrates interactions with OpenIddict's managers and ASP.NET Core Identity to find or create user consent records.
    /// </summary>
    public class AuthorizationPersistenceService : IAuthorizationPersistenceService
    {
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<AuthorizationPersistenceService> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizationPersistenceService"/> class.
        /// </summary>
        /// <param name="authorizationManager">The OpenIddict manager for authorization entities.</param>
        /// <param name="applicationManager">The OpenIddict manager for application entities.</param>
        /// <param name="userManager">The ASP.NET Core manager for user entities.</param>
        /// <param name="logger">The logger for recording service operations.</param>
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

        /// <inheritdoc/>
        public async Task<AppCustomOpenIddictAuthorization?> EnsureAuthorizationAsync(
            ClaimsPrincipal principal,
            ApplicationUser user,
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default)
        {
            // Validate incoming parameters to ensure service contract is met.
            ArgumentNullException.ThrowIfNull(principal);
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(application);

            string userId = await _userManager.GetUserIdAsync(user);
            string? applicationId = await _applicationManager.GetIdAsync(application, cancellationToken);

            if (string.IsNullOrEmpty(applicationId))
            {
                var clientIdForError = await _applicationManager.GetClientIdAsync(application, cancellationToken);
                _logger.LogError("Could not retrieve ID for application {ClientIdentifier}", clientIdForError ?? "UNKNOWN_CLIENT");
                return null;
            }

            // Extract the set of scopes that were granted for this authorization request.
            var principalScopes = principal.GetScopes();

            AppCustomOpenIddictAuthorization? existingMatchingAuthorization = null;
            
            // Search for an existing permanent authorization that matches the user, client, and the exact set of scopes.
            // The FindAsync method returns an IAsyncEnumerable of base objects, which we must iterate through.
            await foreach (var authObject in _authorizationManager.FindAsync(
                subject: userId,
                client: applicationId,
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: principalScopes,
                cancellationToken: cancellationToken
            ).WithCancellation(cancellationToken))
            {
                // Because we configured OpenIddict with `ReplaceDefaultEntities`, the actual object type
                // returned by the manager will be our custom `AppCustomOpenIddictAuthorization`. We must cast it.
                if (authObject is AppCustomOpenIddictAuthorization concreteAuth)
                {
                    existingMatchingAuthorization = concreteAuth;
                    break; // Found a perfect match, no need to check further.
                }
                else if (authObject != null)
                {
                     // This log is a safeguard. It indicates a potential misconfiguration if an object
                     // of an unexpected type is returned by the authorization manager.
                     _logger.LogWarning("Found authorization object of unexpected type {ActualType} during FindAsync. Expected {ExpectedType}.",
                        authObject.GetType().FullName, typeof(AppCustomOpenIddictAuthorization).FullName);
                }
            }
            
            // If a matching authorization was found, return it. This avoids creating duplicate consent records.
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

            // If no match was found, create a new permanent authorization record. This effectively "remembers" the user's consent.
            // The CreateAsync method will internally instantiate our `AppCustomOpenIddictAuthorization` type.
            var newAuthorizationObject = await _authorizationManager.CreateAsync(
                principal: principal,
                subject: userId,
                client: applicationId,
                type: AuthorizationTypes.Permanent,
                scopes: principalScopes,
                cancellationToken: cancellationToken
            );

            // Cast the newly created object to our specific custom type to return it.
            if (newAuthorizationObject is AppCustomOpenIddictAuthorization concreteNewAuth)
            {
                var newAuthId = await _authorizationManager.GetIdAsync(concreteNewAuth, cancellationToken);
                _logger.LogInformation("Successfully created new authorization {NewAuthId}", newAuthId);
                return concreteNewAuth;
            }
            
            // This is an error condition, indicating that the creation failed or returned an unexpected type.
            _logger.LogError(
                "Failed to create new authorization or the created object was not of type {ExpectedType} for user {UserId}, client {ClientId}. Actual type: {ActualType}",
                typeof(AppCustomOpenIddictAuthorization).FullName, userId, applicationId, newAuthorizationObject?.GetType().FullName);
            return null;
        }

        /// <inheritdoc/>
        public async Task<string?> GetAuthorizationIdAsync(
            AppCustomOpenIddictAuthorization authorization,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(authorization);
            // This is a convenience method that delegates the call directly to the OpenIddict manager.
            return await _authorizationManager.GetIdAsync(authorization, cancellationToken);
        }
    }
}