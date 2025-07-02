
// File: Orjnz.IdentityProvider.Web/Pages/Connect/Logout.cshtml.cs
using Microsoft.AspNetCore; // For HttpContext.GetOpenIddictServerRequest() if needed, though not primary here
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization; // To protect POST handler if form is used
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using OpenIddict.Server.AspNetCore; // For OpenIddictServerAspNetCoreDefaults
using Orjnz.IdentityProvider.Web.Data;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Pages.Connect
{
    [ValidateAntiForgeryToken]
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;

        // You might inject IOpenIddictRequestProvider if you need to inspect OIDC logout request parameters
        // like id_token_hint or post_logout_redirect_uri, though OpenIddict handles much of this.

        public LogoutModel(
            SignInManager<ApplicationUser> signInManager,
            ILogger<LogoutModel> logger)
        {
            _signInManager = signInManager;
            _logger = logger;
        }

        /// <summary>
        /// Handles GET requests to the logout page.
        /// Typically displays a logout confirmation form.
        /// </summary>
        public IActionResult OnGet(string? returnUrl = null)
        {
            // You can inspect OpenIddict logout request parameters here if needed
            // var oidcLogoutRequest = HttpContext.GetOpenIddictServerRequest();
            // if (oidcLogoutRequest?.IdTokenHint != null) { ... }
            // if (oidcLogoutRequest?.PostLogoutRedirectUri != null) { ... }

            // Store returnUrl if provided by ASP.NET Core Identity mechanisms (though OIDC post_logout_redirect_uri takes precedence)
            ViewData["ReturnUrl"] = returnUrl;
            return Page(); // Renders Logout.cshtml, which should have a form POSTing to OnPostAsync
        }

        /// <summary>
        /// Handles POST requests from the logout confirmation form or direct POSTs to the logout endpoint.
        /// </summary>
         // Protect against CSRF if this is a direct form post from your UI
        public async Task<IActionResult> OnPostAsync(string? returnUrl = null) // returnUrl from local cookie auth redirect
        {
            // 1. Sign out from ASP.NET Core Identity (clear the local cookie)
            // This is important regardless of whether it's an OIDC logout or just local.
            if (_signInManager.IsSignedIn(User)) // Check if user is actually signed in locally
            {
                await _signInManager.SignOutAsync();
                _logger.LogInformation("User logged out of local ASP.NET Core Identity session.");
            }

            // 2. Trigger OpenIddict's OIDC End Session processing.
            // This will handle validating any OIDC logout parameters (like post_logout_redirect_uri)
            // and performing the necessary OIDC-compliant redirect.
            // The AuthenticationProperties can be used to pass a default redirect URI if no
            // valid post_logout_redirect_uri is found in the OIDC request.
            var properties = new AuthenticationProperties
            {
                // If a local 'returnUrl' was provided (e.g., from a non-OIDC logout link on your site),
                // and no OIDC post_logout_redirect_uri is available or valid,
                // OpenIddict might use this. Defaults to application root if null.
                RedirectUri = returnUrl ?? "/"
            };

            _logger.LogInformation("Initiating OIDC End Session flow.");
            // This SignOutResult is specific to OpenIddict.
            // It tells OpenIddict to process the OIDC end_session_request.
            return SignOut(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
    }
}