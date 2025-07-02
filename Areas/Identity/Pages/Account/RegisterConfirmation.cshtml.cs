// File: Orjnz.IdentityProvider.Web/Areas/Identity/Pages/Account/RegisterConfirmationModel.cshtml.cs
#nullable disable

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
    public class RegisterConfirmationModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<RegisterConfirmationModel> _logger;
        private readonly IConfirmationCodeService _confirmationCodeService;

        public RegisterConfirmationModel(
            UserManager<ApplicationUser> userManager,
            IEmailSender emailSender,
            ILogger<RegisterConfirmationModel> logger,
            IConfirmationCodeService confirmationCodeService)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger;
            _confirmationCodeService = confirmationCodeService;
        }

        public string Email { get; set; }
        public string UserId { get; set; }
        public bool CanResendCode { get; set; } = true;
        public bool HasActiveCode { get; set; }
        
        [TempData]
        public string StatusMessage { get; set; }

        public async Task<IActionResult> OnGetAsync(string email, string returnUrl = null)
        {
            if (string.IsNullOrEmpty(email))
            {
                return RedirectToPage("/Index");
            }

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                // For security, don't reveal if user exists, but still show the page
                Email = email;
                CanResendCode = false;
                HasActiveCode = false;
                return Page();
            }

            if (user.EmailConfirmed)
            {
                // User already confirmed, redirect to login
                return RedirectToPage("./Login", new { area = "Identity", returnUrl = returnUrl });
            }

            Email = email;
            UserId = user.Id;
            
            // Check if there's an active confirmation code
            var codeData = await _confirmationCodeService.GetCodeDataAsync(user.Id);
            HasActiveCode = codeData != null && !codeData.IsExpired && !codeData.IsMaxAttemptsReached;
            CanResendCode = !HasActiveCode;
            
            return Page();
        }

        public async Task<IActionResult> OnPostResendCodeAsync(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                StatusMessage = "Error: Email address is required.";
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                // Don't reveal user doesn't exist, but show success message
                StatusMessage = "If an account with that email exists, a new confirmation code has been sent.";
                Email = email;
                CanResendCode = false;
                HasActiveCode = false;
                return Page();
            }

            if (user.EmailConfirmed)
            {
                return RedirectToPage("./Login", new { area = "Identity" });
            }

            try
            {
                // Generate new codes
                var actualConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                
                // Use the service to generate and store new code
                var displayCode = await _confirmationCodeService.GenerateAndStoreCodeAsync(
                    user.Id, 
                    actualConfirmationToken, 
                    TimeSpan.FromMinutes(15)
                );

                // Send new code
                var userNameForEmail = email.Split('@')[0];
                await _emailSender.SendEmailConfirmationAsync(email, userNameForEmail, displayCode);

                StatusMessage = "A new confirmation code has been sent to your email.";
                HasActiveCode = true;
                CanResendCode = false;
                _logger.LogInformation("Resent confirmation code for user {Email}", email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to resend confirmation code for {Email}", email);
                StatusMessage = "Error: Unable to send confirmation code. Please try again.";
                HasActiveCode = false;
                CanResendCode = true;
            }

            Email = email;
            UserId = user.Id;
            return Page();
        }
    }
}
// // Licensed to the .NET Foundation under one or more agreements.
// // The .NET Foundation licenses this file to you under the MIT license.
// #nullable disable

// using System;
// using System.Text;
// using System.Threading.Tasks;
// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Identity;
// // using Microsoft.AspNetCore.Identity.UI.Services;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.AspNetCore.Mvc.RazorPages;
// using Microsoft.AspNetCore.WebUtilities;
// using Orjnz.IdentityProvider.Web.Data;
// using Orjnz.IdentityProvider.Web.Services;

// namespace Orjnz.IdentityProvider.Web.Areas.Identity.Pages.Account
// {
//     [AllowAnonymous]
//     public class RegisterConfirmationModel : PageModel
//     {
//         private readonly UserManager<ApplicationUser> _userManager;
//         private readonly IEmailSender _sender;

//         public RegisterConfirmationModel(UserManager<ApplicationUser> userManager, IEmailSender sender)
//         {
//             _userManager = userManager;
//             _sender = sender;
//         }

//         /// <summary>
//         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
//         ///     directly from your code. This API may change or be removed in future releases.
//         /// </summary>
//         public string Email { get; set; }

//         /// <summary>
//         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
//         ///     directly from your code. This API may change or be removed in future releases.
//         /// </summary>
//         public bool DisplayConfirmAccountLink { get; set; }

//         /// <summary>
//         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
//         ///     directly from your code. This API may change or be removed in future releases.
//         /// </summary>
//         public string EmailConfirmationUrl { get; set; }

//         public async Task<IActionResult> OnGetAsync(string email, string returnUrl = null)
//         {
//             if (email == null)
//             {
//                 return RedirectToPage("/Index");
//             }
//             returnUrl = returnUrl ?? Url.Content("~/");

//             var user = await _userManager.FindByEmailAsync(email);
//             if (user == null)
//             {
//                 return NotFound($"Unable to load user with email '{email}'.");
//             }

//             Email = email;
//             // Once you add a real email sender, you should remove this code that lets you confirm the account
//             DisplayConfirmAccountLink = true;
//             if (DisplayConfirmAccountLink)
//             {
//                 var userId = await _userManager.GetUserIdAsync(user);
//                 var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
//                 code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
//                 EmailConfirmationUrl = Url.Page(
//                     "/Account/ConfirmEmail",
//                     pageHandler: null,
//                     values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
//                     protocol: Request.Scheme);
//             }

//             return Page();
//         }
//     }
// }
