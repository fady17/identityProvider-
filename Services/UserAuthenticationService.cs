// File: Orjnz.IdentityProvider.Web/Services/UserAuthenticationService.cs
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
    public class UserAuthenticationService : IUserAuthenticationService
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<UserAuthenticationService> _logger;

        public UserAuthenticationService(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            ILogger<UserAuthenticationService> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        public async Task<AuthenticateResult> GetAuthenticationResultAsync(HttpContext httpContext)
        {
            return await httpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        }

        public async Task<ApplicationUser?> GetAuthenticatedUserAsync(ClaimsPrincipal? principal)
        {
            if (principal == null)
            {
                return null;
            }
            return await _userManager.GetUserAsync(principal);
        }

        public bool IsAuthenticationSufficient(AuthenticateResult authResult, OpenIddictRequest oidcRequest)
        {
            if (!authResult.Succeeded) return false;

            if (oidcRequest.HasPrompt(Prompts.Login)) return false;

            if (oidcRequest.MaxAge != null && authResult.Properties?.IssuedUtc != null &&
                DateTimeOffset.UtcNow - authResult.Properties.IssuedUtc > TimeSpan.FromSeconds(oidcRequest.MaxAge.Value))
            {
                return false;
            }
            return true;
        }

        public IActionResult ChallengeForLogin(HttpContext httpContext, string returnUrl)
        {
            // This creates a ChallengeResult that the ASP.NET Core authentication middleware will handle.
            // It will redirect to the configured login path for the IdentityConstants.ApplicationScheme.
            return new ChallengeResult(
                IdentityConstants.ApplicationScheme,
                new AuthenticationProperties { RedirectUri = returnUrl }
            );
        }

        public IActionResult ForbidWithOidcError(string error, string description, string? errorUri = null)
        {
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