// File: Orjnz.IdentityProvider.Web/Services/IUserAuthenticationService.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions; // For OpenIddictRequest
using Orjnz.IdentityProvider.Web.Data; // For ApplicationUser
using System.Security.Claims;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    public interface IUserAuthenticationService
    {
        Task<AuthenticateResult> GetAuthenticationResultAsync(HttpContext httpContext);
        Task<ApplicationUser?> GetAuthenticatedUserAsync(ClaimsPrincipal? principal);
        bool IsAuthenticationSufficient(AuthenticateResult authResult, OpenIddictRequest oidcRequest);
        IActionResult ChallengeForLogin(HttpContext httpContext, string returnUrl);
        IActionResult ForbidWithOidcError(string error, string description, string? errorUri = null);
    }
}