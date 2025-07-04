using Microsoft.AspNetCore.Http; // For HttpContext, QueryString
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc; // For IActionResult
using Microsoft.AspNetCore.Mvc.RazorPages; // For PageModel
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
// using OpenIddict.EntityFrameworkCore.Models; // No longer directly needed if types are custom
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
// using System.Text.Json; // Likely not needed anymore for this service
using System.Threading; // For CancellationToken
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Implements the logic for handling user consent during OIDC authorization flows.
    /// This service determines if consent is needed, displays the consent UI, and processes the user's response.
    /// </summary>
    public class ConsentService : IConsentService
    {
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IClientApplicationService _clientAppService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<ConsentService> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="ConsentService"/> class.
        /// </summary>
        /// <param name="authorizationManager">The OpenIddict manager for authorization entities.</param>
        /// <param name="applicationManager">The OpenIddict manager for application entities.</param>
        /// <param name="scopeManager">The OpenIddict manager for scope entities.</param>
        /// <param name="clientAppService">The custom service for accessing client application details.</param>
        /// <param name="userManager">The ASP.NET Core manager for user entities.</param>
        /// <param name="logger">The logger for recording service operations.</param>
        public ConsentService(
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            IClientApplicationService clientAppService,
            UserManager<ApplicationUser> userManager,
            ILogger<ConsentService> logger)
        {
            _authorizationManager = authorizationManager ?? throw new ArgumentNullException(nameof(authorizationManager));
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
            _scopeManager = scopeManager ?? throw new ArgumentNullException(nameof(scopeManager));
            _clientAppService = clientAppService ?? throw new ArgumentNullException(nameof(clientAppService));
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public async Task<ConsentResult> CheckConsentAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application,
            ImmutableArray<string> requestedScopes,
            OpenIddictRequest oidcRequest,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(application);
            ArgumentNullException.ThrowIfNull(oidcRequest);

            string userId = await _userManager.GetUserIdAsync(user);
            string? applicationId = await _clientAppService.GetApplicationIdAsync(application, cancellationToken);

            if (applicationId == null)
            {
                // This is an integrity check. The application object should always yield a valid ID.
                _logger.LogError("Application ID could not be retrieved for client {ClientId} using application object. Fallback to oidcRequest.ClientId.", oidcRequest.ClientId);
                 return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.ServerError, ErrorDescription: "Application details error: ID mismatch or retrieval failure.");
            }

            // Find all existing permanent authorizations for this user/client that cover the requested scopes.
            var authorizationsFromDb = new List<object>();
            await foreach (var authObject in _authorizationManager.FindAsync(
                subject: userId,
                client : applicationId,
                status : Statuses.Valid,
                type   : AuthorizationTypes.Permanent,
                scopes : requestedScopes,
                cancellationToken: cancellationToken
            ).WithCancellation(cancellationToken))
            {
                authorizationsFromDb.Add(authObject);
            }

            string? applicationConsentType = await _clientAppService.GetApplicationConsentTypeAsync(application, cancellationToken);

            // Case 1: The application is configured to have implicit consent (e.g., a trusted first-party client).
            if (applicationConsentType == ConsentTypes.Implicit)
            {
                _logger.LogInformation("Consent type is Implicit for client {ClientId}. Granting scopes.", oidcRequest.ClientId);
                return new ConsentResult(ConsentStatus.ConsentImplicitlyGranted, requestedScopes);
            }

            // Case 2: The application requires external consent (e.g., granted by an administrator out-of-band).
            // Access is only allowed if a valid authorization already exists.
            if (applicationConsentType == ConsentTypes.External)
            {
                if (!authorizationsFromDb.Any())
                {
                    _logger.LogWarning("External consent type for client {ClientId}, but no matching authorization found for user {UserId}.", oidcRequest.ClientId, userId);
                    return new ConsentResult(ConsentStatus.ConsentDeniedByPolicy, ImmutableArray<string>.Empty, Error: Errors.ConsentRequired, ErrorDescription: "The logged in user is not allowed to access this client application.");
                }
                _logger.LogInformation("External consent type for client {ClientId} and existing authorization found. Granting scopes.", oidcRequest.ClientId);
                return new ConsentResult(ConsentStatus.ConsentGranted, requestedScopes);
            }

            // Case 3: The application requires explicit or systematic user consent.
            if (applicationConsentType == ConsentTypes.Explicit || applicationConsentType == ConsentTypes.Systematic)
            {
                // If a valid authorization already exists and the client hasn't explicitly requested a new consent prompt, we can skip the UI.
                if (authorizationsFromDb.Any() && !oidcRequest.HasPrompt(Prompts.Consent))
                {
                    _logger.LogInformation("Explicit/Systematic consent type for client {ClientId}, existing authorization covers scopes, and no consent prompt. Granting scopes.", oidcRequest.ClientId);
                    return new ConsentResult(ConsentStatus.ConsentGranted, requestedScopes);
                }
                // If the client specified `prompt=none` but consent is required, the request must fail.
                if (oidcRequest.HasPrompt(Prompts.None))
                {
                    _logger.LogWarning("Explicit/Systematic consent required for client {ClientId} but prompt=none specified.", oidcRequest.ClientId);
                    return new ConsentResult(ConsentStatus.ConsentDeniedByPolicy, ImmutableArray<string>.Empty, Error: Errors.InteractionRequired, ErrorDescription: "Interactive user consent is required and prompt=none was specified.");
                }

                // If we reach here, user interaction is required.
                _logger.LogInformation("Explicit/Systematic consent required for client {ClientId}. User interaction needed.", oidcRequest.ClientId);
                string? appDisplayName = await _applicationManager.GetDisplayNameAsync(application, cancellationToken);
                return new ConsentResult(ConsentStatus.ConsentRequired, requestedScopes, ApplicationDisplayName: appDisplayName ?? application.ClientId);
            }

            // This is a fallback for any unhandled or misconfigured consent types.
            _logger.LogError("Unhandled consent scenario for client {ClientId} with consent type {ConsentType}.", oidcRequest.ClientId, applicationConsentType);
            return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.ServerError, ErrorDescription: "Unsupported consent configuration.");
        }

        /// <inheritdoc/>
        public IActionResult DisplayConsentPage(
            PageModel pageModel,
            OpenIddictRequest oidcRequest,
            string applicationDisplayName,
            ImmutableArray<string> scopesRequiringConsent,
            string userId)
        {
            _logger.LogInformation("Redirecting to consent page for client displaying as {ApplicationDisplayName}, user {UserId}.", applicationDisplayName, userId);

            // This method constructs a redirect to the dedicated consent Razor Page,
            // passing necessary context in the route parameters.
            return pageModel.RedirectToPage("/Connect/Consent", new {
                userId = userId,
                clientId = oidcRequest.ClientId
            });
        }

        /// <inheritdoc/>
        public async Task<ConsentResult> ProcessConsentSubmissionAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application,
            ImmutableArray<string> submittedScopes,
            bool wasConsentGranted,
            OpenIddictRequest oidcRequest,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(application);
            ArgumentNullException.ThrowIfNull(oidcRequest);

            // If the user explicitly denied consent, return an access denied error.
            if (!wasConsentGranted)
            {
                _logger.LogInformation("User {UserId} denied consent for client {ClientId}.", user.Id, oidcRequest.ClientId);
                return new ConsentResult(ConsentStatus.ConsentDeniedByUser, ImmutableArray<string>.Empty, Error: Errors.AccessDenied, ErrorDescription: "The resource owner or authorization server denied the request.");
            }

            // Security check: Ensure the scopes submitted by the user were part of the original request.
            var requestedScopesOriginal = oidcRequest.GetScopes();
            if (!submittedScopes.All(ss => requestedScopesOriginal.Contains(ss)))
            {
                _logger.LogError("Consent submission for user {UserId}, client {ClientId} contained scopes not originally requested. Submitted: [{SubmittedScopes}], Original: [{OriginalScopes}]",
                    user.Id, oidcRequest.ClientId, string.Join(", ", submittedScopes), string.Join(", ", requestedScopesOriginal));
                return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.InvalidScope, ErrorDescription: "Invalid scopes submitted during consent.");
            }
            
            // Further validation: Ensure the client application is actually permitted to use the scopes the user granted.
            var clientPermissions = await _clientAppService.GetClientPermissionsAsync(application, cancellationToken);
            
            // Get a list of all scopes defined in the system for validation.
            var allSystemScopeNames = new HashSet<string>();
            await foreach (var scopeObject in _scopeManager.ListAsync(cancellationToken: cancellationToken).WithCancellation(cancellationToken))
            {
                var name = await _scopeManager.GetNameAsync(scopeObject, cancellationToken);
                if (!string.IsNullOrEmpty(name))
                {
                    allSystemScopeNames.Add(name);
                }
            }
            
            // Filter the user-submitted scopes against system-defined scopes and client permissions.
            var finalValidatedSubmittedScopes = new HashSet<string>();
            foreach (var submittedScope in submittedScopes)
            {
                 if ((allSystemScopeNames.Contains(submittedScope) &&
                     clientPermissions.Any(p => p.StartsWith(Permissions.Prefixes.Scope + submittedScope))) ||
                     // The 'openid' and 'offline_access' scopes are fundamental and often don't follow the same permission pattern.
                    submittedScope == Scopes.OpenId || submittedScope == Scopes.OfflineAccess)
                {
                    finalValidatedSubmittedScopes.Add(submittedScope);
                }
                else
                {
                    _logger.LogWarning("Scope '{SubmittedScope}' was submitted by user {UserId} for client {ClientId} but was not ultimately granted due to system/client permission mismatch.",
                        submittedScope, user.Id, application.ClientId);
                }
            }

            if (!finalValidatedSubmittedScopes.Any() && submittedScopes.Any())
            {
                 // This case occurs if the user granted scopes, but none of them were valid for this client.
                 _logger.LogWarning("User {UserId} submitted scopes for client {ClientId}, but none were valid after validation. Initial submission: [{SubmittedScopes}]",
                    user.Id, application.ClientId, string.Join(", ", submittedScopes));
                return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.InvalidScope, ErrorDescription: "No valid scopes were granted based on your selection and application permissions.");
            }
            
            // Return the final, validated set of granted scopes.
            _logger.LogInformation("User {UserId} granted consent for scopes [{GrantedScopes}] for client {ClientId}.", user.Id, string.Join(", ", finalValidatedSubmittedScopes), oidcRequest.ClientId);
            return new ConsentResult(ConsentStatus.ConsentGranted, finalValidatedSubmittedScopes.ToImmutableArray());
        }
    }
}