using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions; // For OpenIddictRequest
using Orjnz.IdentityProvider.Web.Data; // For ApplicationUser
using System.Security.Claims;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Defines the contract for a service that abstracts common user authentication tasks
    /// within an OpenID Connect authorization flow. This service simplifies interactions with
    /// the ASP.NET Core authentication system.
    /// </summary>
    public interface IUserAuthenticationService
    {
        /// <summary>
        /// Retrieves the authentication result for the current HTTP request, typically from the application cookie.
        /// </summary>
        /// <param name="httpContext">The current <see cref="HttpContext"/>.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the <see cref="AuthenticateResult"/>.</returns>
        Task<AuthenticateResult> GetAuthenticationResultAsync(HttpContext httpContext);

        /// <summary>
        /// Retrieves the full <see cref="ApplicationUser"/> object corresponding to an authenticated user's <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> of the authenticated user.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains the
        /// <see cref="ApplicationUser"/> if found; otherwise, <c>null</c>.
        /// </returns>
        Task<ApplicationUser?> GetAuthenticatedUserAsync(ClaimsPrincipal? principal);

        /// <summary>
        /// Determines if the existing user authentication session is sufficient to satisfy the requirements of an OIDC request.
        /// This checks for conditions like `prompt=login` or an expired `max_age`.
        /// </summary>
        /// <param name="authResult">The result from authenticating the user's session.</param>
        /// <param name="oidcRequest">The incoming OpenIddict request from the client application.</param>
        /// <returns><c>true</c> if the current authentication is sufficient; otherwise, <c>false</c>.</returns>
        bool IsAuthenticationSufficient(AuthenticateResult authResult, OpenIddictRequest oidcRequest);

        /// <summary>
        /// Creates an <see cref="IActionResult"/> that challenges the user to log in.
        /// This action triggers a redirect to the configured login page.
        /// </summary>
        /// <param name="httpContext">The current <see cref="HttpContext"/>.</param>
        /// <param name="returnUrl">The URL to redirect the user back to after a successful login.</param>
        /// <returns>An <see cref="IActionResult"/> that initiates the login challenge.</returns>
        IActionResult ChallengeForLogin(HttpContext httpContext, string returnUrl);

        /// <summary>
        /// Creates an <see cref="IActionResult"/> that terminates the OIDC flow and returns a standard
        /// error response to the client application.
        /// </summary>
        /// <param name="error">The OIDC error code (e.g., 'access_denied', 'server_error').</param>
        /// <param name="description">A human-readable description of the error.</param>
        /// <param name="errorUri">An optional URI pointing to a page with more information about the error.</param>
        /// <returns>An <see cref="IActionResult"/> that produces the OIDC error response.</returns>
        IActionResult ForbidWithOidcError(string error, string description, string? errorUri = null);
    }
}