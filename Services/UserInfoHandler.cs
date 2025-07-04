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
    /// <summary>
    /// An OpenIddict server event handler responsible for populating the response of the UserInfo endpoint.
    /// This handler is invoked when a client application makes a valid request to `/connect/userinfo`
    /// with an access token. It fetches the user's data and adds the appropriate claims to the response
    /// based on the scopes granted in the access token.
    /// </summary>
    public class UserInfoHandler : IOpenIddictServerHandler<OpenIddictServerEvents.HandleUserinfoRequestContext>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<UserInfoHandler> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserInfoHandler"/> class.
        /// </summary>
        /// <param name="userManager">The ASP.NET Core manager for user entities.</param>
        /// <param name="logger">The logger for recording handler operations.</param>
        public UserInfoHandler(
            UserManager<ApplicationUser> userManager,
            ILogger<UserInfoHandler> logger)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Asynchronously handles the <see cref="OpenIddictServerEvents.HandleUserinfoRequestContext"/> event.
        /// This method is the entry point for the handler's logic.
        /// </summary>
        /// <param name="context">The context for the UserInfo request event.</param>
        /// <returns>A <see cref="ValueTask"/> that represents the asynchronous handling operation.</returns>
        public async ValueTask HandleAsync(OpenIddictServerEvents.HandleUserinfoRequestContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // By the time this handler is called, OpenIddict has already validated the access token.
            // The `context.Principal` should contain the claims from that token.
            if (context.Principal == null)
            {
                _logger.LogWarning("HandleUserinfoRequestContext.Principal is null. This indicates an issue in prior OpenIddict processing stages.");
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

            // Retrieve the full user object from the database to get up-to-date profile information.
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                // This can happen if the user was deleted after the access token was issued.
                _logger.LogWarning("User with ID {UserId} (from token sub) not found. User might have been deleted.", userId);
                context.Reject(
                    error: Errors.InvalidToken,
                    description: "The user associated with the access token no longer exists."
                );
                return;
            }

            _logger.LogInformation("Handling UserInfo request for user {UserId}. Scopes in token: [{Scopes}]",
                userId, string.Join(", ", context.Principal.GetScopes()));

            // Populate the `context.Claims` dictionary. OpenIddict will use this dictionary
            // to build the final JSON response for the UserInfo endpoint.
            context.Claims[Claims.Subject] = new OpenIddictParameter(userId);

            // Add claims based on the scopes present in the access token.
            if (context.Principal.HasScope(Scopes.Profile))
            {
                _logger.LogDebug("Profile scope present for {UserId}, adding profile claims to UserInfo.", userId);
                if (!string.IsNullOrEmpty(user.UserName))
                    context.Claims[Claims.Name] = new OpenIddictParameter(user.UserName);
                if (!string.IsNullOrEmpty(user.FirstName))
                    context.Claims[Claims.GivenName] = new OpenIddictParameter(user.FirstName);
                if (!string.IsNullOrEmpty(user.LastName))
                    context.Claims[Claims.FamilyName] = new OpenIddictParameter(user.LastName);
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
                }
            }

            // The 'provider_id' claim was added to the access token by ClaimsGenerationService.
            // Here, we simply read it from the token's principal and add it to the UserInfo response.
            var providerIdClaimFromToken = context.Principal.GetClaim("provider_id");
            if (providerIdClaimFromToken != null)
            {
                _logger.LogDebug("provider_id claim found in access token for {UserId}, adding to UserInfo.", userId);
                context.Claims["provider_id"] = new OpenIddictParameter(providerIdClaimFromToken);
            }

            if (context.Principal.HasScope(Scopes.Roles))
            {
                _logger.LogDebug("Roles scope present for {UserId}, adding role claims to UserInfo.", userId);
                var roles = await _userManager.GetRolesAsync(user);
                if (roles.Any())
                {
                    // For multi-valued claims like roles, OpenIddict expects an array.
                    context.Claims[Claims.Role] = new OpenIddictParameter(roles.ToArray());
                }
            }
            
            _logger.LogInformation("Populated {ClaimCount} claims for UserInfo response for user {UserId}.", context.Claims.Count, userId);
            // Completing the method without calling `context.Reject()` signals to OpenIddict that the event was handled successfully.
        }
    }
}