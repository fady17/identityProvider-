#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Services;

namespace Orjnz.IdentityProvider.Web.Areas.Identity.Pages.Account
{
    /// <summary>
    /// This Razor Page model handles the logic for user self-registration.
    /// It captures user input, creates a new user account using ASP.NET Core Identity,
    /// and initiates the email confirmation process.
    /// </summary>
    public class RegisterModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserStore<ApplicationUser> _userStore;
        private readonly IUserEmailStore<ApplicationUser> _emailStore;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailSender _emailSender;
        private readonly IConfirmationCodeService _confirmationCodeService;

        /// <summary>
        /// Initializes a new instance of the <see cref="RegisterModel"/> class.
        /// </summary>
        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore,
            SignInManager<ApplicationUser> signInManager,
            ILogger<RegisterModel> logger,  
            IEmailSender emailSender,
            IConfirmationCodeService confirmationCodeService)
        {
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = GetEmailStore();
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _confirmationCodeService = confirmationCodeService;
        }

        /// <summary>
        /// The model that binds to the registration form's input fields.
        /// </summary>
        [BindProperty]
        public InputModel Input { get; set; }

        /// <summary>
        /// The URL to redirect to after a successful registration and login.
        /// This is often the original `/connect/authorize` URL that initiated the flow.
        /// </summary>
        public string ReturnUrl { get; set; }

        /// <summary>
        /// A list of external authentication providers (e.g., Google, Facebook) configured for the application.
        /// </summary>
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        /// <summary>
        /// Defines the data structure for the registration form input.
        /// </summary>
        public class InputModel
        {
            [Required]
            [EmailAddress]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Required]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
        }

        /// <summary>
        /// Handles the GET request for the registration page, preparing necessary data for the view.
        /// </summary>
        /// <param name="returnUrl">The optional return URL.</param>
        public async Task OnGetAsync(string returnUrl = null)
        {
            ReturnUrl = returnUrl;
            // Fetches any configured external login providers to display on the page.
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        }

        /// <summary>
        /// Handles the POST request from the registration form submission.
        /// </summary>
        /// <param name="returnUrl">The optional return URL.</param>
        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            
            if (ModelState.IsValid)
            {
                var user = CreateUser();

                await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
                await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);
                
                // Attempt to create the user in the database with the provided password.
                var result = await _userManager.CreateAsync(user, Input.Password);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password for email {UserEmail}", Input.Email);
                    var userId = await _userManager.GetUserIdAsync(user);

                    try
                    {
                        // --- Two-Step Email Confirmation Process ---
                        // 1. Generate the secure, long-lived token from ASP.NET Core Identity.
                        // This token is what will actually confirm the email address.
                        var actualConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        _logger.LogInformation("Generated email confirmation token for UserId {UserId}", userId);

                        // 2. Use our custom service to generate a short, user-friendly 6-digit code.
                        // This code is associated with the actual token and stored in a cache with an expiration.
                        var displayCode = await _confirmationCodeService.GenerateAndStoreCodeAsync(
                            userId, 
                            actualConfirmationToken, 
                            TimeSpan.FromMinutes(15)
                        );
                        _logger.LogInformation("Generated and stored 6-digit display code for UserId {UserId}", userId);

                        // 3. Send an email to the user containing only the simple 6-digit display code.
                        var userNameForEmail = Input.Email.Split('@')[0];
                        await _emailSender.SendEmailConfirmationAsync(Input.Email, userNameForEmail, displayCode);
                        _logger.LogInformation("Sent confirmation email to {Email} with display code", Input.Email);

                        // Log the code for debugging purposes, using different log levels for environments.
                        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                        {
                            _logger.LogInformation("DEVELOPMENT ONLY - Confirmation code for {Email} (UserId: {UserId}): {Code}", 
                                Input.Email, userId, displayCode);
                        }
                        else
                        {
                            _logger.LogDebug("Confirmation code generated for UserId {UserId}: {Code}", userId, displayCode);
                        }

                        // As configured in Program.cs, email confirmation is required.
                        if (_userManager.Options.SignIn.RequireConfirmedAccount)
                        {
                            // Redirect to a page where the user can enter the 6-digit code.
                            return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
                        }
                        else
                        {
                            // This block would execute if email confirmation were not required.
                            await _signInManager.SignInAsync(user, isPersistent: false);
                            try
                            {
                                await _emailSender.SendWelcomeEmailAsync(Input.Email, userNameForEmail);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, "Failed to send welcome email to {Email}", Input.Email);
                            }
                            return LocalRedirect(returnUrl);
                        }
                    }
                    catch (Exception ex)
                    {
                        // Handle failures in the confirmation code/email sending process.
                        _logger.LogError(ex, "Failed to send confirmation email for user {Email}", Input.Email);
                        
                        // Even if the email fails, we still want to direct the user to the confirmation page
                        // so they can request a new code.
                        if (_userManager.Options.SignIn.RequireConfirmedAccount)
                        {
                            TempData["StatusMessage"] = "Account created successfully, but there was an issue sending the confirmation email. Please request a new code.";
                            return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
                        }
                        else
                        {
                            await _signInManager.SignInAsync(user, isPersistent: false);
                            return LocalRedirect(returnUrl);
                        }
                    }
                }

                // If user creation failed, add the errors to the model state to be displayed to the user.
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                    _logger.LogWarning("User creation failed for {UserEmail}: {ErrorDescription}", Input.Email, error.Description);
                }
            }

            // If we reach here, model validation failed, so we redisplay the form with error messages.
            return Page();
        }

        /// <summary>
        /// A factory method for creating a new instance of the <see cref="ApplicationUser"/>.
        /// </summary>
        private ApplicationUser CreateUser()
        {
            try
            {
                var user = Activator.CreateInstance<ApplicationUser>();
                user.Id = Guid.NewGuid().ToString(); // Manually set a GUID as the user ID.
                return user;
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'. " +
                    $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor.");
            }
        }

        /// <summary>
        /// A helper method to safely get the email store from the user manager.
        /// </summary>
        private IUserEmailStore<ApplicationUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<ApplicationUser>)_userStore;
        }
    }
}