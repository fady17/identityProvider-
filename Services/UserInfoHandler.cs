// File: Orjnz.IdentityProvider.Web/Services/UserInfoHandler.cs
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
// Correct context type for handling the UserInfo response generation:
using OpenIddict.Server; // For OpenIddictServerEvents if not fully qualified below
using Orjnz.IdentityProvider.Web.Data;
using System;
using System.Linq;
using System.Text.Json.Nodes; // For JsonObject if creating structured claims
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Orjnz.IdentityProvider.Web.Services
{
    // Correctly implement IOpenIddictServerHandler with the specific context type
    public class UserInfoHandler : IOpenIddictServerHandler<OpenIddictServerEvents.HandleUserinfoRequestContext>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<UserInfoHandler> _logger;

        public UserInfoHandler(
            UserManager<ApplicationUser> userManager,
            ILogger<UserInfoHandler> logger)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Handles the UserInfo request event to populate claims.
        /// </summary>
        public async ValueTask HandleAsync(OpenIddictServerEvents.HandleUserinfoRequestContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // At this stage (HandleUserinfoRequestContext), OpenIddict has already validated
            // the access token and context.Principal should be populated.
            if (context.Principal == null)
            {
                _logger.LogWarning("HandleUserinfoRequestContext.Principal is null. This indicates an issue in prior OpenIddict processing stages.");
                // Normally, OpenIddict would have rejected the request before reaching this handler if the token was invalid.
                // If it's null here, it's an unexpected state.
                context.Reject(
                    error: Errors.InvalidToken,
                    description: "The access token is invalid or the principal could not be resolved."
                );
                return;
            }

            var userId = context.Principal.GetClaim(Claims.Subject);
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Subject (sub) claim is missing from the principal in UserInfo request.");
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: "User identifier (subject) is missing from the access token."
                );
                return;
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} (from token sub) not found. User might have been deleted.", userId);
                context.Reject(
                    error: Errors.InvalidToken,
                    description: "The user associated with the access token no longer exists."
                );
                return;
            }

            _logger.LogInformation("Handling UserInfo request for user {UserId}. Scopes in token: [{Scopes}]",
                userId, string.Join(", ", context.Principal.GetScopes()));

            // Populate context.Claims (Dictionary<string, OpenIddictParameter>)
            // This dictionary will be used by OpenIddict to construct the UserInfo JSON response.

            // The 'sub' claim is fundamental and should always be returned.
            // OpenIddict often adds it automatically if not present, but good to be explicit.
            context.Claims[Claims.Subject] = new OpenIddictParameter(userId);

            if (context.Principal.HasScope(Scopes.Profile))
            {
                _logger.LogDebug("Profile scope present for {UserId}, adding profile claims to UserInfo.", userId);
                if (!string.IsNullOrEmpty(user.UserName)) // Or a specific display name property
                    context.Claims[Claims.Name] = new OpenIddictParameter(user.UserName);
                if (!string.IsNullOrEmpty(user.FirstName))
                    context.Claims[Claims.GivenName] = new OpenIddictParameter(user.FirstName);
                if (!string.IsNullOrEmpty(user.LastName))
                    context.Claims[Claims.FamilyName] = new OpenIddictParameter(user.LastName);
                // Add other OIDC profile claims as needed and available
            }

            if (context.Principal.HasScope(Scopes.Email))
            {
                _logger.LogDebug("Email scope present for {UserId}, adding email claims to UserInfo.", userId);
                if (!string.IsNullOrEmpty(user.Email))
                    context.Claims[Claims.Email] = new OpenIddictParameter(user.Email);
                context.Claims[Claims.EmailVerified] = new OpenIddictParameter(user.EmailConfirmed);
            }

            if (context.Principal.HasScope(Scopes.Phone))
            {
                _logger.LogDebug("Phone scope present for {UserId}, adding phone claims to UserInfo.", userId);
                if (!string.IsNullOrEmpty(user.PhoneNumber))
                {
                    context.Claims[Claims.PhoneNumber] = new OpenIddictParameter(user.PhoneNumber);
                    // context.Claims[Claims.PhoneNumberVerified] = new OpenIddictParameter(user.PhoneNumberConfirmed);
                }
            }

            if (context.Principal.HasScope(Scopes.Address))
            {
                // Address construction logic as before
                // var address = new JsonObject(); ...
                // if (address.Count > 0) context.Claims[Claims.Address] = OpenIddictParameter.FromJson(address);
            }
            
            var providerIdClaimFromToken = context.Principal.GetClaim("provider_id");
            if (providerIdClaimFromToken != null)
            {
                _logger.LogDebug("provider_id claim found in access token for {UserId}, adding to UserInfo.", userId);
                context.Claims["provider_id"] = new OpenIddictParameter(providerIdClaimFromToken);
            }
            // else if (user.DefaultProviderId.HasValue && context.Principal.HasScope("some_scope_for_provider_id")) { ... }


            if (context.Principal.HasScope(Scopes.Roles))
            {
                _logger.LogDebug("Roles scope present for {UserId}, adding role claims to UserInfo.", userId);
                var roles = await _userManager.GetRolesAsync(user);
                if (roles.Any())
                {
                    context.Claims[Claims.Role] = new OpenIddictParameter(roles.ToArray());
                }
            }
            
            _logger.LogInformation("Populated {ClaimCount} claims for UserInfo response for user {UserId}.", context.Claims.Count, userId);
            // If HandleAsync completes without calling context.Reject(), OpenIddict considers it handled
            // and will use context.Claims to build the response.
        }
    }
}