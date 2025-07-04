using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens; // For TokenValidationParameters
using OpenIddict.Abstractions;
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.EntityFrameworkCore; // For FirstOrDefaultAsync if needed, and ToListAsync with CT

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Implements the logic for creating a user's <see cref="ClaimsIdentity"/> during an OIDC flow.
    /// This service aggregates user data, roles, and application context to produce a set of claims
    /// that will be included in the issued tokens.
    /// </summary>
    public class ClaimsGenerationService : IClaimsGenerationService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<ClaimsGenerationService> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="ClaimsGenerationService"/> class.
        /// </summary>
        /// <param name="userManager">The ASP.NET Core manager for user entities.</param>
        /// <param name="applicationManager">The OpenIddict manager for application entities.</param>
        /// <param name="scopeManager">The OpenIddict manager for scope entities.</param>
        /// <param name="dbContext">The application's database context for direct data access.</param>
        /// <param name="logger">The logger for recording service operations.</param>
        public ClaimsGenerationService(
            UserManager<ApplicationUser> userManager,
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            ApplicationDbContext dbContext,
            ILogger<ClaimsGenerationService> logger)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
            _scopeManager = scopeManager ?? throw new ArgumentNullException(nameof(scopeManager));
            _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }
        
        /// <inheritdoc/>
        public async Task<ClaimsIdentity> BuildUserClaimsIdentityAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application,
            ImmutableArray<string> grantedScopes,
            OpenIddictRequest oidcRequest,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(application);
            ArgumentNullException.ThrowIfNull(oidcRequest);

            // Create a new claims identity. The authentication type is set to a default
            // that is compatible with standard token validation middleware.
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // === 1. Standard OIDC User Claims ===
            // Populate claims based on the user's profile data and the standard OIDC scopes granted by the user.
            identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user));
            identity.SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user));

            if (grantedScopes.Contains(Scopes.Email))
            {
                identity.SetClaim(Claims.Email, await _userManager.GetEmailAsync(user));
                identity.SetClaim(Claims.EmailVerified, await _userManager.IsEmailConfirmedAsync(user));
            }

            if (grantedScopes.Contains(Scopes.Profile))
            {
                if (!string.IsNullOrEmpty(user.FirstName)) identity.SetClaim(Claims.GivenName, user.FirstName);
                if (!string.IsNullOrEmpty(user.LastName)) identity.SetClaim(Claims.FamilyName, user.LastName);
            }

            if (grantedScopes.Contains(Scopes.Phone))
            {
                if (!string.IsNullOrEmpty(user.PhoneNumber))
                {
                    identity.SetClaim(Claims.PhoneNumber, user.PhoneNumber);
                    // identity.SetClaim(Claims.PhoneNumberVerified, user.PhoneNumberConfirmed);
                }
            }

            // === 2. Role Claims ===
            // If the 'roles' scope was granted, fetch the user's roles and add them as claims.
            if (grantedScopes.Contains(Scopes.Roles))
            {
                var roles = await _userManager.GetRolesAsync(user);
                foreach (var roleName in roles)
                {
                    identity.AddClaim(new Claim(Claims.Role, roleName));
                }
            }

            // === 3. Provider-Specific Context: `provider_id` Claim and API Audience ===
            // This logic determines the multi-tenant context for the token.
            // The primary mechanism is the `ProviderId` property on the client application itself.
            string? primaryApiAudience = null;
            Guid? determinedProviderId = application.ProviderId;

            if (determinedProviderId.HasValue)
            {
                _logger.LogInformation("Application {ClientId} is directly linked to ProviderId: {AppProviderId}. This ProviderId will be used.",
                    application.ClientId, determinedProviderId.Value);
            }
            else
            {
                // This block acts as a fallback or handles scenarios for clients not directly tied to a provider.
                // The logic prefers the user's default provider if the application isn't linked to one.
                if (user.DefaultProviderId.HasValue)
                {
                    _logger.LogInformation("Application {ClientId} has no direct ProviderId. Using User {UserId}'s DefaultProviderId: {UserDefaultProviderId} as the context.",
                        application.ClientId, user.Id, user.DefaultProviderId.Value);
                    determinedProviderId = user.DefaultProviderId;
                }
                else
                {
                    _logger.LogInformation("Application {ClientId} is not linked to a Provider, and user {UserId} has no DefaultProviderId. No 'provider_id' claim will be set from this logic. Audience will be based on general scopes only.",
                        application.ClientId, user.Id);
                }
            }

            // If a provider context was determined, find the provider to set the custom claim and audience.
            if (determinedProviderId.HasValue)
            {
                // Attempt to use the navigation property first if it was eager-loaded.
                Provider? provider = application.Provider;
                // If not loaded or mismatched, fetch directly from the database.
                if (provider == null || provider.Id != determinedProviderId.Value)
                {
                    _logger.LogDebug("Provider entity for ID {ProviderId} not available via navigation property or ID mismatch. Fetching from DbContext for client {ClientId}.",
                        determinedProviderId.Value, application.ClientId);
                    provider = await _dbContext.Providers.FirstOrDefaultAsync(p => p.Id == determinedProviderId.Value && p.IsActive, cancellationToken);
                }

                if (provider != null && provider.IsActive)
                {
                    // Set the custom 'provider_id' claim, which the resource API will use for data tenancy.
                    identity.SetClaim("provider_id", provider.Id.ToString());
                    // Construct a dynamic audience based on the provider's short code. e.g., "clinic1-api".
                    primaryApiAudience = $"{provider.ShortCode}-api";
                    // SetResources adds this audience to the token, primarily for the 'aud' (audience) claim.
                    identity.SetResources(ImmutableArray.Create(primaryApiAudience));
                    _logger.LogInformation("Set 'provider_id' claim to {ProviderId} and determined primary API audience as '{ApiAudience}' for user {UserId}, client {ClientId}.",
                        provider.Id, primaryApiAudience, user.Id, application.ClientId);
                }
                else
                {
                    // This is a potential misconfiguration: a provider ID was resolved, but the provider is missing or inactive.
                    _logger.LogWarning("ProviderId {ResolvedProviderId} was determined, but a valid, active Provider entity was not found in the database. 'provider_id' claim and provider-specific audience will NOT be set for user {UserId}, client {ClientId}.",
                        determinedProviderId.Value, user.Id, application.ClientId);
                }
            }

            // === 4. Set Scopes, Resources (Audiences), and Destinations on the Identity ===
            identity.SetScopes(grantedScopes);

            // Aggregate all resource audiences for the token.
            var resourcesForToken = new HashSet<string>();
            if (!string.IsNullOrEmpty(primaryApiAudience))
            {
                resourcesForToken.Add(primaryApiAudience);
                _logger.LogDebug("Added primary API audience '{PrimaryAudience}' to token resources.", primaryApiAudience);
            }

            // A scope can also be associated with one or more resources (audiences).
            // This loop adds any such resources to the token's audience list.
            if (grantedScopes.Any())
            {
                await foreach (var resourceNameInScope in _scopeManager.ListResourcesAsync(grantedScopes, cancellationToken).WithCancellation(cancellationToken))
                {
                    if (!string.IsNullOrEmpty(resourceNameInScope))
                    {
                        if (resourcesForToken.Add(resourceNameInScope))
                        {
                             _logger.LogDebug("Added audience '{ResourceFromScope}' to token resources from scope definition.", resourceNameInScope);
                        }
                    }
                }
            }

            // A warning for a potential issue where a token might be issued without a clear audience.
            if (!resourcesForToken.Any() && grantedScopes.Any(s => s.StartsWith("api:") || s == Scopes.OfflineAccess))
            {
                _logger.LogWarning("No specific API audience determined and no resources defined on granted scopes for client {ClientId}. Token may lack a specific 'aud' claim or use client_id by default, which could lead to API rejection.",
                    application.ClientId);
            }
            identity.SetResources(resourcesForToken.ToImmutableArray());

            // Set the destinations for each claim (i.e., whether it goes into the access token, ID token, or both).
            identity.SetDestinations(GetDestinations);

            _logger.LogInformation("Built ClaimsIdentity for user {UserId}, Subject: {SubjectClaim}, Scopes: [{GrantedScopes}], Resources: [{TokenResources}] for client {ClientId}",
                user.Id, identity.FindFirst(Claims.Subject)?.Value, string.Join(", ", grantedScopes), string.Join(", ", resourcesForToken), application.ClientId ?? "UnknownClient");

            return identity;
        }

        /// <summary>
        /// A private helper method that determines the destination of a given claim.
        /// The destination controls whether a claim is included in the access token, the ID token, or both.
        /// </summary>
        /// <param name="claim">The claim whose destination is to be determined.</param>
        /// <returns>An enumeration of destination strings (e.g., "access_token", "id_token").</returns>
        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            var identity = claim.Subject;
            if (identity == null) { yield break; }

            // The 'openid' scope must be present for any claims to be included in the ID token.
            bool isOpenIdScopePresent = identity.HasScope(Scopes.OpenId);

            switch (claim.Type)
            {
                // The 'sub' claim is fundamental to both token types.
                case Claims.Subject:
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent) yield return Destinations.IdentityToken;
                    yield break;

                // Claims related to the 'profile' scope.
                case Claims.Name:
                case Claims.PreferredUsername:
                case Claims.GivenName:
                case Claims.FamilyName:
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Profile))
                        yield return Destinations.IdentityToken;
                    yield break;

                // Claims related to the 'email' scope.
                case Claims.Email:
                case Claims.EmailVerified:
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Email))
                        yield return Destinations.IdentityToken;
                    yield break;

                // Claims related to the 'phone' scope.
                case Claims.PhoneNumber:
                     yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Phone))
                        yield return Destinations.IdentityToken;
                    yield break;
                
                // Claims related to the 'address' scope.
                case Claims.Address:
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Address))
                        yield return Destinations.IdentityToken;
                    yield break;

                // Claims related to the 'roles' scope.
                case Claims.Role:
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Roles))
                        yield return Destinations.IdentityToken;
                    yield break;
                
                // Our custom 'provider_id' claim. It's essential for the API (access token)
                // and useful for the client (ID token).
                case "provider_id":
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent)
                        yield return Destinations.IdentityToken;
                    yield break;
                
                // Internal claims like the security stamp should never be exposed in tokens.
                case "AspNet.Identity.SecurityStamp":
                    yield break;

                // Default behavior for any other claims is to include them in the access token.
                default:
                    yield return Destinations.AccessToken;
                    yield break;
            }
        }
    }
}