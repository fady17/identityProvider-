using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Represents the possible outcomes of a consent check or processing operation.
    /// </summary>
    public enum ConsentStatus
    {
        /// <summary>
        /// An unexpected error occurred during consent processing.
        /// </summary>
        Error = 0,
        /// <summary>
        /// The user must be prompted to grant or deny consent.
        /// </summary>
        ConsentRequired = 1,
        /// <summary>
        /// The user has successfully granted consent.
        /// </summary>
        ConsentGranted = 2,
        /// <summary>
        /// Consent was granted automatically based on the client's configuration (e.g., first-party apps).
        /// </summary>
        ConsentImplicitlyGranted = 3,
        /// <summary>
        /// Consent was denied because it violates a configured policy (e.g., prompt=none was specified when consent is required).
        /// </summary>
        ConsentDeniedByPolicy = 4,
        /// <summary>
        /// The user explicitly denied the consent request.
        /// </summary>
        ConsentDeniedByUser = 5
    }

    /// <summary>
    /// A record that encapsulates the result of a consent operation, including its status,
    /// any granted scopes, and potential error details.
    /// </summary>
    /// <param name="Status">The outcome of the consent operation.</param>
    /// <param name="GrantedScopes">The scopes that were successfully granted.</param>
    /// <param name="ApplicationDisplayName">The display name of the client application, used for the consent UI.</param>
    /// <param name="Error">An OIDC-compliant error code (e.g., 'access_denied').</param>
    /// <param name="ErrorDescription">A human-readable description of the error.</param>
    public record ConsentResult(
        ConsentStatus Status,
        ImmutableArray<string> GrantedScopes,
        string? ApplicationDisplayName = null,
        string? Error = null,
        string? ErrorDescription = null);

    /// <summary>
    /// Defines the contract for a service that manages the user consent process in an OIDC flow.
    /// </summary>
    public interface IConsentService
    {
        /// <summary>
        /// Checks if user consent is required for a given authentication request. It evaluates the client's
        /// consent type, any existing authorizations, and OIDC prompt parameters.
        /// </summary>
        /// <param name="user">The authenticated user.</param>
        /// <param name="application">The client application making the request.</param>
        /// <param name="requestedScopes">The scopes requested by the client.</param>
        /// <param name="oidcRequest">The original OpenIddict request object.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A <see cref="ConsentResult"/> indicating the status of the consent check.</returns>
        Task<ConsentResult> CheckConsentAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application,
            ImmutableArray<string> requestedScopes,
            OpenIddictRequest oidcRequest,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Generates an <see cref="IActionResult"/> that redirects the user to the consent page.
        /// This method is responsible for preparing the UI to display the consent challenge.
        /// </summary>
        /// <param name="pageModel">The calling Razor Page model, used to generate the redirect.</param>
        /// <param name="oidcRequest">The original OpenIddict request object.</param>
        /// <param name="applicationDisplayName">The name of the client application to display to the user.</param>
        /// <param name="scopesRequiringConsent">The list of scopes for which consent is being requested.</param>
        /// <param name="userId">The ID of the user who needs to provide consent.</param>
        /// <returns>An <see cref="IActionResult"/> that performs the redirect.</returns>
        IActionResult DisplayConsentPage(
            PageModel pageModel,
            OpenIddictRequest oidcRequest,
            string applicationDisplayName,
            ImmutableArray<string> scopesRequiringConsent,
            string userId);

        /// <summary>
        /// Processes the user's decision from the consent page submission. It validates the submitted
        /// scopes and determines the final outcome of the authorization request.
        /// </summary>
        /// <param name="user">The authenticated user.</param>
        /// <param name="application">The client application.</param>
        /// <param name="submittedScopes">The scopes the user agreed to grant.</param>
        /// <param name="wasConsentGranted">A boolean indicating if the user clicked "Allow" or "Deny".</param>
        /// <param name="oidcRequest">The original OpenIddict request object.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A <see cref="ConsentResult"/> representing the final decision.</returns>
        Task<ConsentResult> ProcessConsentSubmissionAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application,
            ImmutableArray<string> submittedScopes,
            bool wasConsentGranted,
            OpenIddictRequest oidcRequest,
            CancellationToken cancellationToken = default);
    }
}