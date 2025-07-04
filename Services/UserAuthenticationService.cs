using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http; // Required for HttpContext
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc; // Required for IActionResult and controller/page model base classes if used directly
using Microsoft.AspNetCore.Mvc.Infrastructure; // For IActionContextAccessor if creating results manually
using Microsoft.AspNetCore.Mvc.Routing; // For IUrlHelperFactory if creating results manually
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore; // For OpenIddictServerAspNetCoreDefaults
using Orjnz.IdentityProvider.Web.Data;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants; // For Errors, Prompts

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Implements the service for handling common user authentication tasks by leveraging
    /// ASP.NET Core Identity's <see cref="SignInManager{TUser}"/> and <see cref="UserManager{TUser}"/>.
    /// </summary>
    public class UserAuthenticationService : IUserAuthenticationService
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<UserAuthenticationService> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserAuthenticationService"/> class.
        /// </summary>
        /// <param name="signInManager">The ASP.NET Core manager for handling user sign-in operations.</param>
        /// <param name="userManager">The ASP.NET Core manager for user persistence and retrieval.</param>
        /// <param name="logger">The logger for recording service operations.</param>
        public UserAuthenticationService(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            ILogger<UserAuthenticationService> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        /// <inheritdoc/>
        public async Task<AuthenticateResult> GetAuthenticationResultAsync(HttpContext httpContext)
        {
            // Delegates to the ASP.NET Core authentication service to process the request and
            // determine the user's identity based on the application's primary cookie scheme.
            return await httpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        }

        /// <inheritdoc/>
        public async Task<ApplicationUser?> GetAuthenticatedUserAsync(ClaimsPrincipal? principal)
        {
            if (principal == null)
            {
                return null;
            }
            // Uses the UserManager to resolve a ClaimsPrincipal back to the full ApplicationUser entity from the database.
            return await _userManager.GetUserAsync(principal);
        }

        /// <inheritdoc/>
        public bool IsAuthenticationSufficient(AuthenticateResult authResult, OpenIddictRequest oidcRequest)
        {
            // A user must be successfully authenticated for the session to be considered.
            if (!authResult.Succeeded) return false;

            // If the client application explicitly requested a re-authentication via `prompt=login`,
            // the current session is not sufficient, and the user must be challenged again.
            if (oidcRequest.HasPrompt(Prompts.Login)) return false;

            // If the client specified a `max_age` parameter, we must check if the user's session
            // (i.e., when the cookie was issued) is recent enough to satisfy this requirement.
            if (oidcRequest.MaxAge != null && authResult.Properties?.IssuedUtc != null &&
                DateTimeOffset.UtcNow - authResult.Properties.IssuedUtc > TimeSpan.FromSeconds(oidcRequest.MaxAge.Value))
            {
                return false;
            }

            // If all checks pass, the existing authentication is sufficient.
            return true;
        }

        /// <inheritdoc/>
        public IActionResult ChallengeForLogin(HttpContext httpContext, string returnUrl)
        {
            // Creates a ChallengeResult for the main application cookie scheme. The ASP.NET Core
            // authentication middleware intercepts this result and redirects the user to the
            // login page defined in `Program.cs`. The `RedirectUri` ensures the user is
            // returned to the OIDC authorization flow after a successful login.
            return new ChallengeResult(
                IdentityConstants.ApplicationScheme,
                new AuthenticationProperties { RedirectUri = returnUrl }
            );
        }

        /// <inheritdoc/>
        public IActionResult ForbidWithOidcError(string error, string description, string? errorUri = null)
        {
            // Creates a ForbidResult targeting the OpenIddict authentication scheme. This is a special
            // action that OpenIddict's middleware is designed to handle. It will intercept this result
            // and construct a proper OIDC-compliant error response, redirecting back to the
            // client application with the error details in the query string.
            var properties = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
            });

            if (!string.IsNullOrEmpty(errorUri))
            {
                properties.Items[OpenIddictServerAspNetCoreConstants.Properties.ErrorUri] = errorUri;
            }

            return new ForbidResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, properties);
        }
    }
}