// File: Orjnz.IdentityProvider.Web/Areas/Identity/Pages/Account/ConfirmEmailModel.cshtml.cs
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
    [AllowAnonymous]
    public class ConfirmEmailModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<ConfirmEmailModel> _logger;
        private readonly IConfirmationCodeService _confirmationCodeService;

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

        [BindProperty(SupportsGet = true)]
        public string UserId { get; set; }

        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }

        [BindProperty]
        public InputModel Input { get; set; }

        public ApplicationUser CurrentUser { get; set; }
        public int AttemptsRemaining { get; set; } = 3;
        public bool CanResendCode { get; set; } = true;
        public bool IsCodeExpired { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Please enter the 6-digit code.")]
            [Display(Name = "Confirmation Code")]
            [StringLength(6, MinimumLength = 6, ErrorMessage = "The code must be exactly 6 digits.")]
            [RegularExpression(@"^\d{6}$", ErrorMessage = "Please enter a valid 6-digit numeric code.")]
            public string Code { get; set; }
        }

        [TempData]
        public string StatusMessage { get; set; }

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

            if (user.EmailConfirmed)
            {
                StatusMessage = "Your email is already confirmed. You can now sign in.";
                return RedirectToPage("./Login", new { returnUrl = returnUrl });
            }

            CurrentUser = user;
            UserId = userId;
            ReturnUrl = returnUrl ?? Url.Content("~/");

            // Check if confirmation code exists and get status
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
                await _confirmationCodeService.InvalidateCodeAsync(userId);
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
                AttemptsRemaining = Math.Max(0, 3 - codeData.AttemptCount);
                CanResendCode = false;
            }

            return Page();
        }

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

            // Validate the code using the service
            var isValidCode = await _confirmationCodeService.ValidateCodeAsync(UserId, Input.Code);
            
            if (isValidCode)
            {
                // Get the actual token for Identity confirmation
                var codeData = await _confirmationCodeService.GetCodeDataAsync(UserId);
                if (codeData == null)
                {
                    StatusMessage = "Error: Confirmation session expired. Please request a new code.";
                    await LoadUserDataAsync();
                    CanResendCode = true;
                    return Page();
                }

                _logger.LogInformation("User {UserId} entered correct confirmation code", UserId);
                
                var result = await _userManager.ConfirmEmailAsync(user, codeData.ActualToken);
                if (result.Succeeded)
                {
                    StatusMessage = "Thank you for confirming your email! You can now sign in.";
                    _logger.LogInformation("Email confirmed successfully for UserId {UserId}", UserId);

                    // Clean up the confirmation code
                    await _confirmationCodeService.InvalidateCodeAsync(UserId);

                    // Send welcome email
                    try
                    {
                        var userNameForEmail = user.Email.Split('@')[0];
                        await _emailSender.SendWelcomeEmailAsync(user.Email, userNameForEmail);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to send welcome email to {Email}", user.Email);
                    }

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
                // Increment attempts and get current count
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
                    // The service will handle max attempts, so we don't need to invalidate manually
                }
            }

            await LoadUserDataAsync();
            return Page();
        }

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
                // Generate new codes
                var actualConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                
                // Use the service to generate and store new code
                var displayCode = await _confirmationCodeService.GenerateAndStoreCodeAsync(
                    UserId, 
                    actualConfirmationToken, 
                    TimeSpan.FromMinutes(15)
                );

                // Send new code
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

        private async Task LoadUserDataAsync()
        {
            if (!string.IsNullOrEmpty(UserId))
            {
                CurrentUser = await _userManager.FindByIdAsync(UserId);
                
                // Get current code status
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