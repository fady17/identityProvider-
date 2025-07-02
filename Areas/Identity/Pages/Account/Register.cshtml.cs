#nullable disable
// File: Orjnz.IdentityProvider.Web/Areas/Identity/Pages/Account/RegisterModel.cshtml.cs
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
    public class RegisterModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserStore<ApplicationUser> _userStore;
        private readonly IUserEmailStore<ApplicationUser> _emailStore;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailSender _emailSender;
        private readonly IConfirmationCodeService _confirmationCodeService;

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

        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

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

        public async Task OnGetAsync(string returnUrl = null)
        {
            ReturnUrl = returnUrl;
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            
            if (ModelState.IsValid)
            {
                var user = CreateUser();

                await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
                await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);
                var result = await _userManager.CreateAsync(user, Input.Password);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password for email {UserEmail}", Input.Email);
                    var userId = await _userManager.GetUserIdAsync(user);

                    try
                    {
                        // Generate the actual token that Identity uses for confirmation
                        var actualConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        _logger.LogInformation("Generated email confirmation token for UserId {UserId}", userId);

                        // Use the ConfirmationCodeService to generate and store the code
                        var displayCode = await _confirmationCodeService.GenerateAndStoreCodeAsync(
                            userId, 
                            actualConfirmationToken, 
                            TimeSpan.FromMinutes(15)
                        );

                        _logger.LogInformation("Generated and stored 6-digit display code for UserId {UserId}", userId);

                        // Send confirmation email with 6-digit code
                        var userNameForEmail = Input.Email.Split('@')[0];
                        await _emailSender.SendEmailConfirmationAsync(Input.Email, userNameForEmail, displayCode);
                        _logger.LogInformation("Sent confirmation email to {Email} with display code", Input.Email);

                        // LOG THE ACTUAL CODE - Use different log levels based on environment
                        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                        {
                            // In development, log at Information level for easy debugging
                            _logger.LogInformation("DEVELOPMENT ONLY - Confirmation code for {Email} (UserId: {UserId}): {Code}", 
                                Input.Email, userId, displayCode);
                        }
                        else
                        {
                            // In production, log at Debug level (won't show unless debug logging is enabled)
                            _logger.LogDebug("Confirmation code generated for UserId {UserId}: {Code}", userId, displayCode);
                        }

                        if (_userManager.Options.SignIn.RequireConfirmedAccount)
                        {
                            // Redirect to confirmation page that shows instructions and allows code entry
                            return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
                        }
                        else
                        {
                            // If email confirmation is not required, sign in the user immediately
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
                        _logger.LogError(ex, "Failed to send confirmation email for user {Email}", Input.Email);
                        
                        // Even if email sending fails, we should still redirect to confirmation page
                        // The user can request a resend from there
                        if (_userManager.Options.SignIn.RequireConfirmedAccount)
                        {
                            TempData["StatusMessage"] = "Account created successfully, but there was an issue sending the confirmation email. Please request a new code.";
                            return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
                        }
                        else
                        {
                            // If confirmation is not required, sign them in anyway
                            await _signInManager.SignInAsync(user, isPersistent: false);
                            return LocalRedirect(returnUrl);
                        }
                    }
                }

                // Handle registration errors
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                    _logger.LogWarning("User creation failed for {UserEmail}: {ErrorDescription}", Input.Email, error.Description);
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }

        private ApplicationUser CreateUser()
        {
            try
            {
                var user = Activator.CreateInstance<ApplicationUser>();
                user.Id = Guid.NewGuid().ToString();
                return user;
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'. " +
                    $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the register page in /Areas/Identity/Pages/Account/Register.cshtml");
            }
        }

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
// // Licensed to the .NET Foundation under one or more agreements.
// // The .NET Foundation licenses this file to you under the MIT license.
// #nullable disable

// using System;
// using System.Collections.Generic;
// using System.ComponentModel.DataAnnotations;
// using System.Linq;
// using System.Text;
// using System.Text.Encodings.Web;
// using System.Threading;
// using System.Threading.Tasks;
// using Microsoft.AspNetCore.Authentication;
// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Identity;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.AspNetCore.Mvc.RazorPages;
// using Microsoft.AspNetCore.WebUtilities;
// using Microsoft.Extensions.Logging;
// using Orjnz.IdentityProvider.Web.Data;
// using Orjnz.IdentityProvider.Web.Services;

// namespace Orjnz.IdentityProvider.Web.Areas.Identity.Pages.Account
// {
//     public class RegisterModel : PageModel
//     {
//         private readonly SignInManager<ApplicationUser> _signInManager;
//         private readonly UserManager<ApplicationUser> _userManager;
//         private readonly IUserStore<ApplicationUser> _userStore;
//         private readonly IUserEmailStore<ApplicationUser> _emailStore;
//         private readonly ILogger<RegisterModel> _logger;
//         private readonly IEmailSender _emailSender;

//         public RegisterModel(
//             UserManager<ApplicationUser> userManager,
//             IUserStore<ApplicationUser> userStore,
//             SignInManager<ApplicationUser> signInManager,
//             ILogger<RegisterModel> logger,  
//             IEmailSender emailSender)
//         {
//             _userManager = userManager;
//             _userStore = userStore;
//             _emailStore = GetEmailStore();
//             _signInManager = signInManager;
//             _logger = logger;
//             _emailSender = emailSender;
//         }

//         /// <summary>
//         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
//         ///     directly from your code. This API may change or be removed in future releases.
//         /// </summary>
//         [BindProperty]
//         public InputModel Input { get; set; }

//         /// <summary>
//         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
//         ///     directly from your code. This API may change or be removed in future releases.
//         /// </summary>
//         public string ReturnUrl { get; set; }

//         /// <summary>
//         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
//         ///     directly from your code. This API may change or be removed in future releases.
//         /// </summary>
//         public IList<AuthenticationScheme> ExternalLogins { get; set; }

//         /// <summary>
//         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
//         ///     directly from your code. This API may change or be removed in future releases.
//         /// </summary>
//         public class InputModel
//         {
//             /// <summary>
//             ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
//             ///     directly from your code. This API may change or be removed in future releases.
//             /// </summary>
//             [Required]
//             [EmailAddress]
//             [Display(Name = "Email")]
//             public string Email { get; set; }

//             /// <summary>
//             ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
//             ///     directly from your code. This API may change or be removed in future releases.
//             /// </summary>
//             [Required]
//             [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
//             [DataType(DataType.Password)]
//             [Display(Name = "Password")]
//             public string Password { get; set; }

//             /// <summary>
//             ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
//             ///     directly from your code. This API may change or be removed in future releases.
//             /// </summary>
//             [DataType(DataType.Password)]
//             [Display(Name = "Confirm password")]
//             [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
//             public string ConfirmPassword { get; set; }
//         }

//         public async Task OnGetAsync(string returnUrl = null)
//         {
//             ReturnUrl = returnUrl;
//             ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
//         }
// //         // File: Orjnz.IdentityProvider.Web/Areas/Identity/Pages/Account/RegisterModel.cshtml.cs
// // public async Task<IActionResult> OnPostAsync(string returnUrl = null)
// // {
// //     returnUrl ??= Url.Content("~/");
// //     ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
// //     if (ModelState.IsValid)
// //     {
// //         var user = CreateUser();

// //         await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
// //         await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);
// //         var result = await _userManager.CreateAsync(user, Input.Password);

// //         if (result.Succeeded)
// //         {
// //             _logger.LogInformation("User created a new account with password for email {UserEmail}", Input.Email);
// //             var userId = await _userManager.GetUserIdAsync(user);

// //             // Generate the actual token that Identity uses for confirmation (long string)
// //             var actualConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
// //             _logger.LogInformation("Generated actual email confirmation token for UserId {UserId}: (Token Hidden)", userId); // Don't log the actual token unless in verbose debug

// //             // Generate a 6-digit code for the user to type
// //             var random = new Random();
// //             var sixDigitDisplayCode = random.Next(100000, 999999).ToString("D6");
// //             _logger.LogInformation("Generated 6-digit display code for UserId {UserId}: {DisplayCode}", userId, sixDigitDisplayCode);

// //             TempData[$"EmailConfirmationToken_{userId}"] = actualConfirmationToken;
// //             TempData[$"DisplayCode_{userId}"] = sixDigitDisplayCode;
// //             TempData.Keep(); 
// //             // TODO: Store the sixDigitDisplayCode and/or actualConfirmationToken temporarily and securely,
// //                     // associated with the userId, with an expiry. For example, using IDistributedCache:
// //                     // await _distributedCache.SetStringAsync($"EmailConfirmation:User:{userId}:DisplayCode", sixDigitDisplayCode, new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15) });
// //                     // await _distributedCache.SetStringAsync($"EmailConfirmation:User:{userId}:ActualToken", actualConfirmationToken, new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15) });
// //                     // For now, we'll pass the actual token (encoded) to the confirmation page via query string for simplicity
// //                     // if we were to still use a link, but for code entry, the ConfirmEmail page will regenerate it.
// //             _logger.LogInformation("Stored actual token and display code for UserId {UserId}", userId);

// //             var userNameForEmail = Input.Email.Split('@')[0];
// //             await _emailSender.SendEmailConfirmationAsync(Input.Email, userNameForEmail, sixDigitDisplayCode); // Send the 6-digit code

// //             if (_userManager.Options.SignIn.RequireConfirmedAccount)
// //             {
// //                 // Redirect to a page that tells the user to check their email for a code.
// //                 // This page could also be the one where they enter the code.
// //                 // For now, RegisterConfirmation will just show "check your email".
// //                 // We will need a new page like "ConfirmEmailByCode.cshtml"
// //                 return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
// //             }
// //             else
// //             {
// //                 await _signInManager.SignInAsync(user, isPersistent: false);
// //                 await _emailSender.SendWelcomeEmailAsync(Input.Email, userNameForEmail);
// //                 return LocalRedirect(returnUrl);
// //             }
// //         }
// //         foreach (var error in result.Errors)
// //         {
// //             ModelState.AddModelError(string.Empty, error.Description);
// //             _logger.LogWarning("User creation failed for {UserEmail}: {ErrorDescription}", Input.Email, error.Description);
// //         }
// //     }
// //     return Page();
// // }

// // Improved OnPostAsync method for RegisterModel.cs
// public async Task<IActionResult> OnPostAsync(string returnUrl = null)
// {
//     returnUrl ??= Url.Content("~/");
//     ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
    
//     if (ModelState.IsValid)
//     {
//         var user = CreateUser();

//         await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
//         await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);
//         var result = await _userManager.CreateAsync(user, Input.Password);

//         if (result.Succeeded)
//         {
//             _logger.LogInformation("User created a new account with password for email {UserEmail}", Input.Email);
//             var userId = await _userManager.GetUserIdAsync(user);

//             try
//             {
//                 // Generate the actual token that Identity uses for confirmation
//                 var actualConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
//                 _logger.LogInformation("Generated email confirmation token for UserId {UserId}", userId);

//                 // Generate a 6-digit code for the user to type
//                 var random = new Random();
//                 var sixDigitDisplayCode = random.Next(100000, 999999).ToString("D6");
//                 _logger.LogInformation("Generated 6-digit display code for UserId {UserId}: {DisplayCode}", userId, sixDigitDisplayCode);

//                 // Store tokens with expiration (using TempData for now, but consider IDistributedCache for production)
//                 TempData[$"EmailConfirmationToken_{userId}"] = actualConfirmationToken;
//                 TempData[$"DisplayCode_{userId}"] = sixDigitDisplayCode;
//                 TempData[$"CodeGeneratedTime_{userId}"] = DateTime.UtcNow.ToString("O"); // ISO format for parsing
//                 TempData.Keep();

//                 // TODO: For production, use IDistributedCache instead of TempData:
//                 /*
//                 var cacheOptions = new DistributedCacheEntryOptions
//                 {
//                     AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15)
//                 };
//                 await _distributedCache.SetStringAsync($"EmailConfirmation:User:{userId}:DisplayCode", sixDigitDisplayCode, cacheOptions);
//                 await _distributedCache.SetStringAsync($"EmailConfirmation:User:{userId}:ActualToken", actualConfirmationToken, cacheOptions);
//                 */

//                 // Send confirmation email with 6-digit code
//                 var userNameForEmail = Input.Email.Split('@')[0];
//                 await _emailSender.SendEmailConfirmationAsync(Input.Email, userNameForEmail, sixDigitDisplayCode);
//                 _logger.LogInformation("Sent confirmation email to {Email} with display code", Input.Email);

//                 if (_userManager.Options.SignIn.RequireConfirmedAccount)
//                 {
//                     // Redirect to confirmation page that shows instructions and allows code entry
//                     return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
//                 }
//                 else
//                 {
//                     // If email confirmation is not required, sign in the user immediately
//                     await _signInManager.SignInAsync(user, isPersistent: false);
//                     try
//                     {
//                         await _emailSender.SendWelcomeEmailAsync(Input.Email, userNameForEmail);
//                     }
//                     catch (Exception ex)
//                     {
//                         _logger.LogWarning(ex, "Failed to send welcome email to {Email}", Input.Email);
//                     }
//                     return LocalRedirect(returnUrl);
//                 }
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to send confirmation email for user {Email}", Input.Email);
                
//                 // Even if email sending fails, we should still redirect to confirmation page
//                 // The user can request a resend from there
//                 if (_userManager.Options.SignIn.RequireConfirmedAccount)
//                 {
//                     TempData["StatusMessage"] = "Account created successfully, but there was an issue sending the confirmation email. Please request a new code.";
//                     return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
//                 }
//                 else
//                 {
//                     // If confirmation is not required, sign them in anyway
//                     await _signInManager.SignInAsync(user, isPersistent: false);
//                     return LocalRedirect(returnUrl);
//                 }
//             }
//         }

//         // Handle registration errors
//         foreach (var error in result.Errors)
//         {
//             ModelState.AddModelError(string.Empty, error.Description);
//             _logger.LogWarning("User creation failed for {UserEmail}: {ErrorDescription}", Input.Email, error.Description);
//         }
//     }

//     // If we got this far, something failed, redisplay form
//     return Page();
// }        private ApplicationUser CreateUser()
//         {
//             try
//             {
//                 var user = Activator.CreateInstance<ApplicationUser>();

//                 user.Id = Guid.NewGuid().ToString(); // Generate and assign a new string ID
//                 // =====================
//                 return user;
//             }
//             catch
//             {
//                 throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'. " +
//                     $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
//                     $"override the register page in /Areas/Identity/Pages/Account/Register.cshtml");
//             }
//         }

//         private IUserEmailStore<ApplicationUser> GetEmailStore()
//         {
//             if (!_userManager.SupportsUserEmail)
//             {
//                 throw new NotSupportedException("The default UI requires a user store with email support.");
//             }
//             return (IUserEmailStore<ApplicationUser>)_userStore;
//         }
//     }
// }
// // // Licensed to the .NET Foundation under one or more agreements.
// // // The .NET Foundation licenses this file to you under the MIT license.
// // #nullable disable

// // using System;
// // using System.Collections.Generic;
// // using System.ComponentModel.DataAnnotations;
// // using System.Linq;
// // using System.Text;
// // using System.Text.Encodings.Web;
// // using System.Threading;
// // using System.Threading.Tasks;
// // using Microsoft.AspNetCore.Authentication;
// // using Microsoft.AspNetCore.Authorization;
// // using Microsoft.AspNetCore.Identity;

// // using Microsoft.AspNetCore.Mvc;
// // using Microsoft.AspNetCore.Mvc.RazorPages;
// // using Microsoft.AspNetCore.WebUtilities;
// // using Microsoft.Extensions.Logging;
// // using Orjnz.IdentityProvider.Web.Data;
// // using Orjnz.IdentityProvider.Web.Services;

// // namespace Orjnz.IdentityProvider.Web.Areas.Identity.Pages.Account
// // {
// //     public class RegisterModel : PageModel
// //     {
// //         private readonly SignInManager<ApplicationUser> _signInManager;
// //         private readonly UserManager<ApplicationUser> _userManager;
// //         private readonly IUserStore<ApplicationUser> _userStore;
// //         private readonly IUserEmailStore<ApplicationUser> _emailStore;
// //         private readonly ILogger<RegisterModel> _logger;
// //         private readonly IEmailSender _emailSender;

// //         public RegisterModel(
// //             UserManager<ApplicationUser> userManager,
// //             IUserStore<ApplicationUser> userStore,
// //             SignInManager<ApplicationUser> signInManager,
// //             ILogger<RegisterModel> logger,  
// //             IEmailSender emailSender)
// //         {
// //             _userManager = userManager;
// //             _userStore = userStore;
// //             _emailStore = GetEmailStore();
// //             _signInManager = signInManager;
// //             _logger = logger;
// //             _emailSender = emailSender;
// //         }

// //         /// <summary>
// //         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
// //         ///     directly from your code. This API may change or be removed in future releases.
// //         /// </summary>
// //         [BindProperty]
// //         public InputModel Input { get; set; }

// //         /// <summary>
// //         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
// //         ///     directly from your code. This API may change or be removed in future releases.
// //         /// </summary>
// //         public string ReturnUrl { get; set; }

// //         /// <summary>
// //         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
// //         ///     directly from your code. This API may change or be removed in future releases.
// //         /// </summary>
// //         public IList<AuthenticationScheme> ExternalLogins { get; set; }

// //         /// <summary>
// //         ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
// //         ///     directly from your code. This API may change or be removed in future releases.
// //         /// </summary>
// //         public class InputModel
// //         {
// //             /// <summary>
// //             ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
// //             ///     directly from your code. This API may change or be removed in future releases.
// //             /// </summary>
// //             [Required]
// //             [EmailAddress]
// //             [Display(Name = "Email")]
// //             public string Email { get; set; }

// //             /// <summary>
// //             ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
// //             ///     directly from your code. This API may change or be removed in future releases.
// //             /// </summary>
// //             [Required]
// //             [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
// //             [DataType(DataType.Password)]
// //             [Display(Name = "Password")]
// //             public string Password { get; set; }

// //             /// <summary>
// //             ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
// //             ///     directly from your code. This API may change or be removed in future releases.
// //             /// </summary>
// //             [DataType(DataType.Password)]
// //             [Display(Name = "Confirm password")]
// //             [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
// //             public string ConfirmPassword { get; set; }
// //         }


// //         public async Task OnGetAsync(string returnUrl = null)
// //         {
// //             ReturnUrl = returnUrl;
// //             ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
// //         }

// //         public async Task<IActionResult> OnPostAsync(string returnUrl = null)
// //         {
// //             returnUrl ??= Url.Content("~/");
// //             ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
// //             if (ModelState.IsValid)
// //             {
// //                 var user = CreateUser();

// //                 await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
// //                 await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);
// //                 var result = await _userManager.CreateAsync(user, Input.Password);

// //                 if (result.Succeeded)
// //                 {
// //                     _logger.LogInformation("User created a new account with password.");

// //                     var userId = await _userManager.GetUserIdAsync(user);
// //                     var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
// //                     code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
// //                     var callbackUrl = Url.Page(
// //                         "/Account/ConfirmEmail",
// //                         pageHandler: null,
// //                         values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
// //                         protocol: Request.Scheme);

// //                     await _emailSender.SendEmailAsync(Input.Email, "Confirm your email",
// //                         $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

// //                     if (_userManager.Options.SignIn.RequireConfirmedAccount)
// //                     {
// //                         return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
// //                     }
// //                     else
// //                     {
// //                         await _signInManager.SignInAsync(user, isPersistent: false);
// //                         return LocalRedirect(returnUrl);
// //                     }
// //                 }
// //                 foreach (var error in result.Errors)
// //                 {
// //                     ModelState.AddModelError(string.Empty, error.Description);
// //                 }
// //             }

// //             // If we got this far, something failed, redisplay form
// //             return Page();
// //         }

// //         private ApplicationUser CreateUser()
// //         {
// //             try
// //             {
// //                 return Activator.CreateInstance<ApplicationUser>();
// //             }
// //             catch
// //             {
// //                 throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'. " +
// //                     $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
// //                     $"override the register page in /Areas/Identity/Pages/Account/Register.cshtml");
// //             }
// //         }

// //         private IUserEmailStore<ApplicationUser> GetEmailStore()
// //         {
// //             if (!_userManager.SupportsUserEmail)
// //             {
// //                 throw new NotSupportedException("The default UI requires a user store with email support.");
// //             }
// //             return (IUserEmailStore<ApplicationUser>)_userStore;
// //         }
// //     }
// // }
