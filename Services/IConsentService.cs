// File: Orjnz.IdentityProvider.Web/Services/IConsentService.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
// No longer need direct reference to OpenIddict.EntityFrameworkCore.Models if AppCustom is used
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System.Collections.Immutable;
using System.Threading; // For CancellationToken
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    public enum ConsentStatus
    {
        Error = 0,
        ConsentRequired = 1,
        ConsentGranted = 2,
        ConsentImplicitlyGranted = 3,
        ConsentDeniedByPolicy = 4,
        ConsentDeniedByUser = 5
    }

    public record ConsentResult(
        ConsentStatus Status,
        ImmutableArray<string> GrantedScopes,
        string? ApplicationDisplayName = null,
        string? Error = null,
        string? ErrorDescription = null);

    public interface IConsentService
    {
        Task<ConsentResult> CheckConsentAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application, // Changed parameter type
            ImmutableArray<string> requestedScopes,
            OpenIddictRequest oidcRequest,
            CancellationToken cancellationToken = default); // Added CancellationToken

        // DisplayConsentPage is synchronous and UI-related, typically doesn't need CancellationToken for its own logic.
        // The PageModel it redirects to might have async handlers that take a CancellationToken.
        IActionResult DisplayConsentPage(
            PageModel pageModel,
            OpenIddictRequest oidcRequest,
            string applicationDisplayName,
            ImmutableArray<string> scopesRequiringConsent,
            string userId);

        Task<ConsentResult> ProcessConsentSubmissionAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application, // Changed parameter type
            ImmutableArray<string> submittedScopes,
            bool wasConsentGranted,
            OpenIddictRequest oidcRequest,
            CancellationToken cancellationToken = default); // Added CancellationToken
    }
}