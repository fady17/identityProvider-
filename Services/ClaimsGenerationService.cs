// File: Orjnz.IdentityProvider.Web/Services/ClaimsGenerationService.cs
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
    public class ClaimsGenerationService : IClaimsGenerationService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IOpenIddictApplicationManager _applicationManager; // For GetClientIdAsync for logging
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<ClaimsGenerationService> _logger;

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

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // === 1. Standard OIDC User Claims ===
            // These claims are populated based on the user's profile and granted OIDC scopes.
            identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user));
            identity.SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user)); // Typically the username or a display name

            if (grantedScopes.Contains(Scopes.Email))
            {
                identity.SetClaim(Claims.Email, await _userManager.GetEmailAsync(user));
                identity.SetClaim(Claims.EmailVerified, await _userManager.IsEmailConfirmedAsync(user));
            }

            if (grantedScopes.Contains(Scopes.Profile))
            {
                if (!string.IsNullOrEmpty(user.FirstName)) identity.SetClaim(Claims.GivenName, user.FirstName);
                if (!string.IsNullOrEmpty(user.LastName)) identity.SetClaim(Claims.FamilyName, user.LastName);
                // Consider adding:
                // identity.SetClaim(Claims.PreferredUsername, user.UserName); // If different from 'name'
                // identity.SetClaim(Claims.Picture, user.ProfilePictureUrl); // TODO
                // identity.SetClaim(Claims.UpdatedAt, new DateTimeOffset(user.UpdatedAt).ToUnixTimeSeconds()); 
            }

            if (grantedScopes.Contains(Scopes.Phone))
            {
                if (!string.IsNullOrEmpty(user.PhoneNumber))
                {
                    identity.SetClaim(Claims.PhoneNumber, user.PhoneNumber);
                    // identity.SetClaim(Claims.PhoneNumberVerified, user.PhoneNumberConfirmed); //TODO
                }
            }

            // === 2. Role Claims ===
            // Roles are added if the 'roles' scope is granted.
            if (grantedScopes.Contains(Scopes.Roles))
            {
                var roles = await _userManager.GetRolesAsync(user);
                foreach (var roleName in roles)
                {
                    identity.AddClaim(new Claim(Claims.Role, roleName));
                }
            }

            // === 3. Provider-Specific Context: `provider_id` Claim and API Audience ===
            // This section determines the provider context for the token, which influences
            // the 'provider_id' claim and the primary API audience.
            string? primaryApiAudience = null; // This will be the main audience for the provider's API
            Guid? determinedProviderId = application.ProviderId; // Directly use the strongly-typed property from the linked application

            if (determinedProviderId.HasValue)
            {
                _logger.LogInformation("Application {ClientId} is directly linked to ProviderId: {AppProviderId}. This ProviderId will be used.",
                    application.ClientId, determinedProviderId.Value);
            }
            else
            {
                // SCENARIO: Application is NOT directly linked to a Provider via its ProviderId property.
                // Based on your requirement ("all providers should have provider-specific app no generic clients"),
                // an application *should* ideally always have a ProviderId if it's meant to access provider-specific resources.
                // The fallback to user.DefaultProviderId might be removed or used only for very specific "portal" type clients
                // that are NOT provider-specific apps.
                // For now, let's keep the user.DefaultProviderId logic but be mindful of its implications.
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

            if (determinedProviderId.HasValue)
            {
                // Attempt to load the Provider entity to get its ShortCode for the audience
                // and to confirm it's an active, valid provider.
                Provider? provider = application.Provider; // Try navigation property first (if eager-loaded)
                if (provider == null || provider.Id != determinedProviderId.Value) // Ensure nav property is for the correct provider
                {
                    _logger.LogDebug("Provider entity for ID {ProviderId} not available via navigation property or ID mismatch. Fetching from DbContext for client {ClientId}.",
                        determinedProviderId.Value, application.ClientId);
                    provider = await _dbContext.Providers.FirstOrDefaultAsync(p => p.Id == determinedProviderId.Value && p.IsActive, cancellationToken);
                }

                if (provider != null && provider.IsActive)
                {
                    identity.SetClaim("provider_id", provider.Id.ToString());
                    primaryApiAudience = $"{provider.ShortCode}-api"; // e.g., "testclinic-api"
                     identity.SetResources(ImmutableArray.Create(primaryApiAudience));
                    _logger.LogInformation("Set 'provider_id' claim to {ProviderId} and determined primary API audience as '{ApiAudience}' for user {UserId}, client {ClientId}.",
                        provider.Id, primaryApiAudience, user.Id, application.ClientId);
                }
                else
                {
                    _logger.LogWarning("ProviderId {ResolvedProviderId} was determined, but a valid, active Provider entity was not found in the database. 'provider_id' claim and provider-specific audience will NOT be set for user {UserId}, client {ClientId}.",
                        determinedProviderId.Value, user.Id, application.ClientId);
                    // If a ProviderId was expected (e.g., from application.ProviderId) but the Provider is not found/inactive,
                    // this is a potential misconfiguration. You might choose to throw an error or prevent token issuance
                    // if this context is critical for the client's operation.
                    // For now, primaryApiAudience remains null, and no provider_id claim is added.
                }
            }
            // else: No provider context determined (e.g. a truly global client not tied to any provider or user default)
            // The 'gis-platform-webapp' specific check is removed as per "no generic clients" for provider services.
            // If you have other types of clients (e.g., IDP admin client), their audience logic would go here.


            // === 4. Set Scopes, Resources (Audiences), and Destinations on the Identity ===
            identity.SetScopes(grantedScopes);

            var resourcesForToken = new HashSet<string>();
            if (!string.IsNullOrEmpty(primaryApiAudience))
            {
                resourcesForToken.Add(primaryApiAudience);
                _logger.LogDebug("Added primary API audience '{PrimaryAudience}' to token resources.", primaryApiAudience);
            }

            // Add resources that are directly defined on the granted scopes themselves.
            // This allows scopes to be associated with other, potentially shared, resource servers.
            if (grantedScopes.Any())
            {
                await foreach (var resourceNameInScope in _scopeManager.ListResourcesAsync(grantedScopes, cancellationToken).WithCancellation(cancellationToken))
                {
                    if (!string.IsNullOrEmpty(resourceNameInScope))
                    {
                        if (resourcesForToken.Add(resourceNameInScope)) // Add returns true if item was added
                        {
                             _logger.LogDebug("Added audience '{ResourceFromScope}' to token resources from scope definition.", resourceNameInScope);
                        }
                    }
                }
            }

            // Ensure there's at least one audience if scopes implying resources were granted.
            // OpenIddict might default to client_id if no audience, or token validation might fail.
            if (!resourcesForToken.Any() && grantedScopes.Any(s => s.StartsWith("api:") || s == Scopes.OfflineAccess)) // Heuristic for API scopes
            {
                _logger.LogWarning("No specific API audience determined and no resources defined on granted scopes for client {ClientId}. Token may lack a specific 'aud' claim or use client_id by default, which could lead to API rejection.",
                    application.ClientId);
                // Consider adding application.ClientId as a fallback audience if appropriate for your model:
                // if (application.ClientId != null) resourcesForToken.Add(application.ClientId);
            }
            identity.SetResources(resourcesForToken.ToImmutableArray());

            identity.SetDestinations(GetDestinations);

            _logger.LogInformation("Built ClaimsIdentity for user {UserId}, Subject: {SubjectClaim}, Scopes: [{GrantedScopes}], Resources: [{TokenResources}] for client {ClientId}",
                user.Id, identity.FindFirst(Claims.Subject)?.Value, string.Join(", ", grantedScopes), string.Join(", ", resourcesForToken), application.ClientId ?? "UnknownClient");

            return identity;
        }

        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            var identity = claim.Subject;
            if (identity == null) { yield break; } // Should have an identity

            // Standard OIDC practice: sub is always in id_token.
            // Other claims in id_token if 'openid' and the relevant scope (profile, email, etc.) are present.
            // All granted claims typically go into the access token for API use.

            bool isOpenIdScopePresent = identity.HasScope(Scopes.OpenId);

            switch (claim.Type)
            {
                case Claims.Subject:
                    yield return Destinations.AccessToken; // Often useful in access token too
                    if (isOpenIdScopePresent) yield return Destinations.IdentityToken;
                    yield break;

                case Claims.Name:
                case Claims.PreferredUsername:
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Profile))
                        yield return Destinations.IdentityToken;
                    yield break;

                case Claims.GivenName:
                case Claims.FamilyName:
                // Potentially other profile claims: picture, website, gender, birthdate, zoneinfo, locale, updated_at
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Profile))
                        yield return Destinations.IdentityToken;
                    yield break;

                case Claims.Email:
                case Claims.EmailVerified:
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Email))
                        yield return Destinations.IdentityToken;
                    yield break;

                case Claims.PhoneNumber:
                // case Claims.PhoneNumberVerified:
                     yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Phone))
                        yield return Destinations.IdentityToken;
                    yield break;
                
                case Claims.Address: // Address is a structured claim
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Address))
                        yield return Destinations.IdentityToken;
                    yield break;

                case Claims.Role:
                    yield return Destinations.AccessToken;
                    if (isOpenIdScopePresent && identity.HasScope(Scopes.Roles))
                        yield return Destinations.IdentityToken;
                    yield break;
                
                case "provider_id": // Your custom claim
                    yield return Destinations.AccessToken; // Essential for the provider's API
                    if (isOpenIdScopePresent) // Generally good to include in ID token if 'openid' scope
                        yield return Destinations.IdentityToken;
                    yield break;
                
                // OpenIddict specific internal claims (auth_time, nonce, at_hash, c_hash etc.) are handled by OpenIddict for ID token.
                // You don't typically set destinations for these.

                case "AspNet.Identity.SecurityStamp": // Security stamp should NEVER be in external tokens.
                    yield break;

                default:
                    // For any other custom claims or less common standard claims,
                    // default to including them in the access token.
                    // Only add to ID token if specifically needed by client and within OIDC best practices.
                    yield return Destinations.AccessToken;
                    yield break;
            }
        }
    }
}
