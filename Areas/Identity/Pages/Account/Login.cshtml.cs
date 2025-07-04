#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
// using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Orjnz.IdentityProvider.Web.Data;

namespace Orjnz.IdentityProvider.Web.Areas.Identity.Pages.Account
{
    /// <summary>
    /// This Razor Page model handles the user login functionality. It validates user credentials
    /// against the configured user store and establishes a sign-in session (cookie) upon success.
    /// This page is typically displayed when a user is challenged for authentication during an OIDC flow.
    /// </summary>
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="LoginModel"/> class.
        /// </summary>
        /// <param name="signInManager">The ASP.NET Core service for managing user sign-in operations.</param>
        /// <param name="logger">The logger for recording login events.</param>
        public LoginModel(SignInManager<ApplicationUser> signInManager, ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _logger = logger;
        }

        /// <summary>
        /// This model binds to the login form's input fields.
        /// It is part of the ASP.NET Core Identity default UI.
        /// </summary>
        [BindProperty]
        public InputModel Input { get; set; }

        /// <summary>
        /// A list of external authentication providers (e.g., Google, Facebook) configured for the application.
        /// It is part of the ASP.NET Core Identity default UI.
        /// </summary>
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        /// <summary>
        /// The URL to redirect to after a successful login. In an OIDC flow, this is usually
        /// the `/connect/authorize` endpoint, which continues the authorization process.
        /// It is part of the ASP.NET Core Identity default UI.
        /// </summary>
        public string ReturnUrl { get; set; }

        /// <summary>
        /// A property to hold and display any error messages passed to the page.
        /// It is part of the ASP.NET Core Identity default UI.
        /// </summary>
        [TempData]
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Defines the data structure for the login form input.
        /// It is part of the ASP.NET Core Identity default UI.
        /// </summary>
        public class InputModel
        {
            /// <summary>
            /// The user's email address.
            /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            /// directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            /// <summary>
            /// The user's password.
            /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            /// directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            /// <summary>
            /// A flag indicating whether the user's login session should be persisted across browser sessions.
            /// This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            /// directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        /// <summary>
        /// Handles the GET request for the login page, preparing necessary data for the view.
        /// </summary>
        /// <param name="returnUrl">The optional return URL.</param>
        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        /// <summary>
        /// Handles the POST request from the login form submission.
        /// </summary>
        /// <param name="returnUrl">The optional return URL.</param>
        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                // Attempt to sign the user in with their provided password.
                // lockoutOnFailure is set to false, meaning failed attempts here won't lock the account.
                // To enable lockout, this should be set to true and lockout settings configured in Program.cs.
                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    // After a successful login, redirect the user back to the ReturnUrl.
                    return LocalRedirect(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    // If the user has 2FA enabled, redirect them to the 2FA login page.
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    // If the user's account is locked out, redirect them to the lockout information page.
                    _logger.LogWarning("User account locked out.");
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    // For any other failure (e.g., incorrect password), display a generic error message.
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }

            // If model validation failed, redisplay the form with error messages.
            return Page();
        }
    }
}