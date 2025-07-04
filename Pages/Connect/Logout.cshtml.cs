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
    /// <summary>
    /// This Razor Page model handles the user logout process. It is responsible for both
    /// signing the user out of their local ASP.NET Core Identity session (clearing the cookie)
    /// and initiating the OpenID Connect (OIDC) End-Session flow, which handles redirecting
    /// the user back to the client application after logout.
    /// </summary>
    [ValidateAntiForgeryToken] // Protects the POST handler from Cross-Site Request Forgery (CSRF) attacks.
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="LogoutModel"/> class.
        /// </summary>
        /// <param name="signInManager">The ASP.NET Core service for managing user sign-in operations.</param>
        /// <param name="logger">The logger for recording logout events.</param>
        public LogoutModel(
            SignInManager<ApplicationUser> signInManager,
            ILogger<LogoutModel> logger)
        {
            _signInManager = signInManager;
            _logger = logger;
        }

        /// <summary>
        /// Handles GET requests to the logout page.
        /// This method's primary purpose is to display the logout confirmation view (Logout.cshtml).
        /// The view should contain a form that POSTs to the `OnPostAsync` handler to confirm the logout action.
        /// </summary>
        /// <param name="returnUrl">An optional URL for non-OIDC local logouts.</param>
        public IActionResult OnGet(string? returnUrl = null)
        {
            // OIDC-specific parameters like `post_logout_redirect_uri` are automatically
            // handled by the OpenIddict middleware when the final SignOutResult is returned in OnPostAsync.
            // This method simply prepares the confirmation page.
            ViewData["ReturnUrl"] = returnUrl;
            return Page();
        }

        /// <summary>
        /// Handles the POST request from the logout confirmation form. This is the core of the logout logic.
        /// </summary>
        /// <param name="returnUrl">An optional URL passed from the local logout form.</param>
        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            // Step 1: Sign the user out of the local authentication scheme.
            // This clears the ASP.NET Core Identity cookie, ending the user's session with the Identity Provider.
            if (_signInManager.IsSignedIn(User))
            {
                await _signInManager.SignOutAsync();
                _logger.LogInformation("User logged out of local ASP.NET Core Identity session.");
            }

            // Step 2: Trigger the OIDC End-Session flow.
            // This is done by returning a special SignOutResult targeting the OpenIddict scheme.
            var properties = new AuthenticationProperties
            {
                // The RedirectUri serves as a fallback. If the original OIDC request contained a valid
                // `post_logout_redirect_uri` that is registered with the client, OpenIddict will use that.
                // Otherwise, it may use this local URL.
                RedirectUri = returnUrl ?? "/"
            };

            _logger.LogInformation("Initiating OIDC End Session flow.");
            
            // The OpenIddict middleware intercepts this specific SignOutResult. It processes the OIDC
            // end-session request and performs the necessary redirect to the client application,
            // completing the federated logout process.
            return SignOut(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
    }
}