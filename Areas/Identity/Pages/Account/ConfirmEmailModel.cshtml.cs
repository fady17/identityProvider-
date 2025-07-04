#nullable disable
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Services;
using Microsoft.Extensions.Logging;

namespace Orjnz.IdentityProvider.Web.Areas.Identity.Pages.Account
{
    /// <summary>
    /// This Razor Page model handles the logic for confirming a user's email address.
    /// It's designed to work with the two-step confirmation process where a user enters
    /// a 6-digit code sent to their email.
    /// </summary>
    [AllowAnonymous]
    public class ConfirmEmailModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<ConfirmEmailModel> _logger;
        private readonly IConfirmationCodeService _confirmationCodeService;

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfirmEmailModel"/> class.
        /// </summary>
        public ConfirmEmailModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ILogger<ConfirmEmailModel> logger,
            IConfirmationCodeService confirmationCodeService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _logger = logger;
            _confirmationCodeService = confirmationCodeService;
        }

        /// <summary>
        /// The unique identifier for the user whose email is being confirmed.
        /// This is passed in the URL from the registration process.
        /// </summary>
        [BindProperty(SupportsGet = true)]
        public string UserId { get; set; }

        /// <summary>
        // The URL to return to after successful confirmation.
        /// </summary>
        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }

        /// <summary>
        /// The model that binds to the confirmation form's input fields.
        /// </summary>
        [BindProperty]
        public InputModel Input { get; set; }

        /// <summary>
        /// The user object, loaded to display user-specific information like their email address.
        /// </summary>
        public ApplicationUser CurrentUser { get; set; }

        /// <summary>
        /// The number of remaining attempts the user has to enter the correct code.
        /// </summary>
        public int AttemptsRemaining { get; set; } = 3;

        /// <summary>
        /// A flag to control whether the "Resend Code" button is displayed.
        /// </summary>
        public bool CanResendCode { get; set; } = true;

        /// <summary>
        /// A flag indicating if the current confirmation code has expired.
        /// </summary>
        public bool IsCodeExpired { get; set; }

        /// <summary>
        /// Defines the data structure for the confirmation form input.
        /// </summary>
        public class InputModel
        {
            [Required(ErrorMessage = "Please enter the 6-digit code.")]
            [Display(Name = "Confirmation Code")]
            [StringLength(6, MinimumLength = 6, ErrorMessage = "The code must be exactly 6 digits.")]
            [RegularExpression(@"^\d{6}$", ErrorMessage = "Please enter a valid 6-digit numeric code.")]
            public string Code { get; set; }
        }

        /// <summary>
        /// A message to display to the user (e.g., success or error notifications).
        /// </summary>
        [TempData]
        public string StatusMessage { get; set; }

        /// <summary>
        /// Handles the GET request for the email confirmation page. It validates the user and
        /// sets the initial state of the page (e.g., attempts remaining).
        /// </summary>
        public async Task<IActionResult> OnGetAsync(string userId, string returnUrl = null)
        {
            if (string.IsNullOrEmpty(userId))
            {
                StatusMessage = "Error: User ID is missing. Please try the registration process again.";
                return RedirectToPage("./Register");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                StatusMessage = "Error: Invalid confirmation link. Please try registering again.";
                return RedirectToPage("./Register");
            }

            // If the user's email is already confirmed, no action is needed.
            if (user.EmailConfirmed)
            {
                StatusMessage = "Your email is already confirmed. You can now sign in.";
                return RedirectToPage("./Login", new { returnUrl = returnUrl });
            }

            CurrentUser = user;
            UserId = userId;
            ReturnUrl = returnUrl ?? Url.Content("~/");

            // Check the status of the confirmation code from the cache.
            var codeData = await _confirmationCodeService.GetCodeDataAsync(userId);
            if (codeData == null)
            {
                _logger.LogWarning("No confirmation code data found for UserId {UserId}. User may need new code.", userId);
                StatusMessage = "Your confirmation session may have expired. Please request a new code.";
                CanResendCode = true;
            }
            else if (codeData.IsExpired)
            {
                _logger.LogWarning("Confirmation code expired for UserId {UserId}", userId);
                StatusMessage = "Your confirmation code has expired. Please request a new code.";
                IsCodeExpired = true;
                CanResendCode = true;
                await _confirmationCodeService.InvalidateCodeAsync(userId); // Clean up expired code
            }
            else if (codeData.IsMaxAttemptsReached)
            {
                _logger.LogWarning("Max attempts reached for confirmation code for UserId {UserId}", userId);
                StatusMessage = "Too many incorrect attempts. Please request a new confirmation code.";
                AttemptsRemaining = 0;
                CanResendCode = true;
            }
            else
            {
                // If the code is active, calculate remaining attempts.
                AttemptsRemaining = Math.Max(0, 3 - codeData.AttemptCount);
                CanResendCode = false; // Don't allow resend if a valid code is active.
            }

            return Page();
        }

        /// <summary>
        /// Handles the POST request from the confirmation form submission.
        /// </summary>
        public async Task<IActionResult> OnPostAsync()
        {
            ReturnUrl = ReturnUrl ?? Url.Content("~/");

            if (string.IsNullOrEmpty(UserId))
            {
                _logger.LogError("UserId is missing on POST in ConfirmEmail");
                StatusMessage = "Error: Session expired. Please try the confirmation process again.";
                return RedirectToPage("./Register");
            }

            if (!ModelState.IsValid)
            {
                await LoadUserDataAsync();
                return Page();
            }

            var user = await _userManager.FindByIdAsync(UserId);
            if (user == null)
            {
                StatusMessage = "Error: Invalid user. Please try registering again.";
                return RedirectToPage("./Register");
            }
            
            if (user.EmailConfirmed)
            {
                StatusMessage = "Your email is already confirmed.";
                return RedirectToPage("./Login", new { ReturnUrl = ReturnUrl });
            }

            // Use the service to validate the user-entered 6-digit code.
            var isValidCode = await _confirmationCodeService.ValidateCodeAsync(UserId, Input.Code);
            
            if (isValidCode)
            {
                // If the display code is valid, retrieve the associated actual (secure) token.
                var codeData = await _confirmationCodeService.GetCodeDataAsync(UserId);
                if (codeData == null)
                {
                    StatusMessage = "Error: Confirmation session expired. Please request a new code.";
                    await LoadUserDataAsync();
                    CanResendCode = true;
                    return Page();
                }

                _logger.LogInformation("User {UserId} entered correct confirmation code", UserId);
                
                // Use the actual token to confirm the email with ASP.NET Core Identity.
                var result = await _userManager.ConfirmEmailAsync(user, codeData.ActualToken);
                if (result.Succeeded)
                {
                    StatusMessage = "Thank you for confirming your email! You can now sign in.";
                    _logger.LogInformation("Email confirmed successfully for UserId {UserId}", UserId);
                    await _confirmationCodeService.InvalidateCodeAsync(UserId);

                    try
                    {
                        var userNameForEmail = user.Email.Split('@')[0];
                        await _emailSender.SendWelcomeEmailAsync(user.Email, userNameForEmail);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to send welcome email to {Email}", user.Email);
                    }

                    // Redirect to login, passing the original returnUrl if it exists.
                    return RedirectToPage("./Login", new { area = "Identity", returnUrl = ReturnUrl });
                }
                else
                {
                    StatusMessage = "Error confirming your email. The confirmation token may have expired.";
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                        _logger.LogWarning("Error confirming email for UserId {UserId}: {Error}", UserId, error.Description);
                    }
                }
            }
            else
            {
                // If the code is incorrect, increment the attempt counter.
                var attemptCount = await _confirmationCodeService.IncrementAttemptsAsync(UserId);
                AttemptsRemaining = Math.Max(0, 3 - attemptCount);
                _logger.LogWarning("User {UserId} entered incorrect confirmation code. Attempt {Attempt}/3", UserId, attemptCount);

                if (AttemptsRemaining > 0)
                {
                    StatusMessage = $"Incorrect code. You have {AttemptsRemaining} attempt{(AttemptsRemaining == 1 ? "" : "s")} remaining.";
                    ModelState.AddModelError(nameof(Input.Code), "The confirmation code is incorrect.");
                }
                else
                {
                    StatusMessage = "Too many incorrect attempts. Please request a new confirmation code.";
                    CanResendCode = true;
                }
            }
            
            // Reload user data to refresh the page state and re-display the form.
            await LoadUserDataAsync();
            return Page();
        }

        /// <summary>
        /// Handles the POST request to resend a confirmation code.
        /// </summary>
        public async Task<IActionResult> OnPostResendCodeAsync()
        {
            if (string.IsNullOrEmpty(UserId))
            {
                StatusMessage = "Error: User ID is missing.";
                return Page();
            }

            var user = await _userManager.FindByIdAsync(UserId);
            if (user == null || user.EmailConfirmed)
            {
                return RedirectToPage("./Login");
            }

            try
            {
                // Generate a new secure token and a new display code.
                var actualConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var displayCode = await _confirmationCodeService.GenerateAndStoreCodeAsync(
                    UserId, 
                    actualConfirmationToken, 
                    TimeSpan.FromMinutes(15)
                );

                var userNameForEmail = user.Email.Split('@')[0];
                await _emailSender.SendEmailConfirmationAsync(user.Email, userNameForEmail, displayCode);

                StatusMessage = "A new confirmation code has been sent to your email.";
                AttemptsRemaining = 3;
                CanResendCode = false;
                IsCodeExpired = false;
                _logger.LogInformation("Resent confirmation code for UserId {UserId}", UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to resend confirmation code for UserId {UserId}", UserId);
                StatusMessage = "Error: Unable to send confirmation code. Please try again.";
            }

            await LoadUserDataAsync();
            return Page();
        }

        /// <summary>
        /// A helper method to reload user and code status data to refresh the page's properties.
        /// </summary>
        private async Task LoadUserDataAsync()
        {
            if (!string.IsNullOrEmpty(UserId))
            {
                CurrentUser = await _userManager.FindByIdAsync(UserId);
                
                var codeData = await _confirmationCodeService.GetCodeDataAsync(UserId);
                if (codeData != null)
                {
                    AttemptsRemaining = Math.Max(0, 3 - codeData.AttemptCount);
                    IsCodeExpired = codeData.IsExpired;
                    CanResendCode = codeData.IsExpired || codeData.IsMaxAttemptsReached;
                }
            }
        }
    }
}