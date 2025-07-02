// File: Orjnz.IdentityProvider.Web/Services/ConsentService.cs
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
    public class ConsentService : IConsentService
    {
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictApplicationManager _applicationManager; // Still useful for GetDisplayNameAsync on base type
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IClientApplicationService _clientAppService; // Use this to get custom app details
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<ConsentService> _logger;

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

        public async Task<ConsentResult> CheckConsentAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application, // Changed parameter type
            ImmutableArray<string> requestedScopes,
            OpenIddictRequest oidcRequest,
            CancellationToken cancellationToken = default) // Added CancellationToken
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(application);
            ArgumentNullException.ThrowIfNull(oidcRequest);

            string userId = await _userManager.GetUserIdAsync(user); // Does not take CT
            string? applicationId = await _clientAppService.GetApplicationIdAsync(application, cancellationToken);

            if (applicationId == null)
            {
                _logger.LogError("Application ID could not be retrieved for client {ClientId} using application object. Fallback to oidcRequest.ClientId.", oidcRequest.ClientId);
                // If GetApplicationIdAsync fails, we might still proceed if oidcRequest.ClientId is reliable,
                // but it's a sign that 'application' object might be problematic.
                // For FindAsync below, we need a valid applicationId.
                // Let's assume ClientId from oidcRequest is the ultimate source of truth for identifying the client app.
                // However, the 'application' object is used for GetApplicationConsentTypeAsync.
                // This indicates a potential issue if GetApplicationIdAsync returns null for a valid app object.
                 return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.ServerError, ErrorDescription: "Application details error: ID mismatch or retrieval failure.");
            }

            var authorizationsFromDb = new List<object>();
            await foreach (var authObject in _authorizationManager.FindAsync(
                subject: userId,
                client : applicationId, // Use the retrieved applicationId
                status : Statuses.Valid,
                type   : AuthorizationTypes.Permanent,
                scopes : requestedScopes,
                cancellationToken: cancellationToken
            ).WithCancellation(cancellationToken))
            {
                authorizationsFromDb.Add(authObject);
            }

            string? applicationConsentType = await _clientAppService.GetApplicationConsentTypeAsync(application, cancellationToken);

            // Case 1: Implicit consent type for the application.
            if (applicationConsentType == ConsentTypes.Implicit)
            {
                _logger.LogInformation("Consent type is Implicit for client {ClientId}. Granting scopes.", oidcRequest.ClientId);
                return new ConsentResult(ConsentStatus.ConsentImplicitlyGranted, requestedScopes);
            }

            // Case 2: External consent type (e.g., admin pre-approved).
            if (applicationConsentType == ConsentTypes.External)
            {
                if (!authorizationsFromDb.Any())
                {
                    _logger.LogWarning("External consent type for client {ClientId}, but no matching authorization found for user {UserId}.", oidcRequest.ClientId, userId);
                    return new ConsentResult(ConsentStatus.ConsentDeniedByPolicy, ImmutableArray<string>.Empty, Error: Errors.ConsentRequired, ErrorDescription: "The logged in user is not allowed to access this client application.");
                }
                _logger.LogInformation("External consent type for client {ClientId} and existing authorization found. Granting scopes.", oidcRequest.ClientId);
                return new ConsentResult(ConsentStatus.ConsentGranted, requestedScopes); // Previously granted by admin
            }

            // Case 3: Explicit or Systematic consent types.
            if (applicationConsentType == ConsentTypes.Explicit || applicationConsentType == ConsentTypes.Systematic)
            {
                if (authorizationsFromDb.Any() && !oidcRequest.HasPrompt(Prompts.Consent))
                {
                    _logger.LogInformation("Explicit/Systematic consent type for client {ClientId}, existing authorization covers scopes, and no consent prompt. Granting scopes.", oidcRequest.ClientId);
                    return new ConsentResult(ConsentStatus.ConsentGranted, requestedScopes); // Previously granted by user
                }

                if (oidcRequest.HasPrompt(Prompts.None))
                {
                    _logger.LogWarning("Explicit/Systematic consent required for client {ClientId} but prompt=none specified.", oidcRequest.ClientId);
                    return new ConsentResult(ConsentStatus.ConsentDeniedByPolicy, ImmutableArray<string>.Empty, Error: Errors.InteractionRequired, ErrorDescription: "Interactive user consent is required and prompt=none was specified.");
                }

                _logger.LogInformation("Explicit/Systematic consent required for client {ClientId}. User interaction needed.", oidcRequest.ClientId);
                // GetDisplayNameAsync can take the base type. Application is AppCustom... which inherits from it.
                string? appDisplayName = await _applicationManager.GetDisplayNameAsync(application, cancellationToken);
                return new ConsentResult(ConsentStatus.ConsentRequired, requestedScopes, ApplicationDisplayName: appDisplayName ?? application.ClientId);
            }

            _logger.LogError("Unhandled consent scenario for client {ClientId} with consent type {ConsentType}.", oidcRequest.ClientId, applicationConsentType);
            return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.ServerError, ErrorDescription: "Unsupported consent configuration.");
        }


        public IActionResult DisplayConsentPage(
            PageModel pageModel,
            OpenIddictRequest oidcRequest,
            string applicationDisplayName,
            ImmutableArray<string> scopesRequiringConsent,
            string userId)
        {
            _logger.LogInformation("Redirecting to consent page for client displaying as {ApplicationDisplayName}, user {UserId}.", applicationDisplayName, userId);

            // Pass client_id and userId to the consent page.
            // The consent page will retrieve the full OIDC request from HttpContext if needed.
            return pageModel.RedirectToPage("/Connect/Consent", new {
                userId = userId,
                clientId = oidcRequest.ClientId
                // Other parameters are passed to ConsentModel.OnGet via route values from AuthorizeModel.
            });
        }

        public async Task<ConsentResult> ProcessConsentSubmissionAsync(
            ApplicationUser user,
            AppCustomOpenIddictApplication application, // Changed parameter type
            ImmutableArray<string> submittedScopes,
            bool wasConsentGranted,
            OpenIddictRequest oidcRequest,
            CancellationToken cancellationToken = default) // Added CancellationToken
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(application);
            ArgumentNullException.ThrowIfNull(oidcRequest);

            if (!wasConsentGranted)
            {
                _logger.LogInformation("User {UserId} denied consent for client {ClientId}.", user.Id, oidcRequest.ClientId);
                return new ConsentResult(ConsentStatus.ConsentDeniedByUser, ImmutableArray<string>.Empty, Error: Errors.AccessDenied, ErrorDescription: "The resource owner or authorization server denied the request.");
            }

            var requestedScopesOriginal = oidcRequest.GetScopes();
            if (!submittedScopes.All(ss => requestedScopesOriginal.Contains(ss)))
            {
                _logger.LogError("Consent submission for user {UserId}, client {ClientId} contained scopes not originally requested. Submitted: [{SubmittedScopes}], Original: [{OriginalScopes}]",
                    user.Id, oidcRequest.ClientId, string.Join(", ", submittedScopes), string.Join(", ", requestedScopesOriginal));
                return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.InvalidScope, ErrorDescription: "Invalid scopes submitted during consent.");
            }

            var clientPermissions = await _clientAppService.GetClientPermissionsAsync(application, cancellationToken);
            
            var allSystemScopeNames = new HashSet<string>();
            await foreach (var scopeObject in _scopeManager.ListAsync(cancellationToken: cancellationToken).WithCancellation(cancellationToken))
            {
                var name = await _scopeManager.GetNameAsync(scopeObject, cancellationToken);
                if (!string.IsNullOrEmpty(name))
                {
                    allSystemScopeNames.Add(name);
                }
            }

            var finalValidatedSubmittedScopes = new HashSet<string>();
            foreach (var submittedScope in submittedScopes)
            {
                 if ((allSystemScopeNames.Contains(submittedScope) &&
                     clientPermissions.Any(p => p.StartsWith(Permissions.Prefixes.Scope + submittedScope))) ||
                    submittedScope == Scopes.OpenId || submittedScope == Scopes.OfflineAccess) // Always allow these if client asks
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
                 _logger.LogWarning("User {UserId} submitted scopes for client {ClientId}, but none were valid after validation. Initial submission: [{SubmittedScopes}]",
                    user.Id, application.ClientId, string.Join(", ", submittedScopes));
                return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.InvalidScope, ErrorDescription: "No valid scopes were granted based on your selection and application permissions.");
            }

            _logger.LogInformation("User {UserId} granted consent for scopes [{GrantedScopes}] for client {ClientId}.", user.Id, string.Join(", ", finalValidatedSubmittedScopes), oidcRequest.ClientId);
            return new ConsentResult(ConsentStatus.ConsentGranted, finalValidatedSubmittedScopes.ToImmutableArray());
        }
    }
}
// // File: Orjnz.IdentityProvider.Web/Services/ConsentService.cs
// using Microsoft.AspNetCore.Http; // For HttpContext, QueryString
// using Microsoft.AspNetCore.Identity;
// using Microsoft.AspNetCore.Mvc; // For IActionResult
// using Microsoft.AspNetCore.Mvc.RazorPages; // For PageModel
// using Microsoft.Extensions.Logging;
// using OpenIddict.Abstractions;
// using OpenIddict.EntityFrameworkCore.Models; // For OpenIddictEntityFrameworkCoreAuthorization, OpenIddictEntityFrameworkCoreApplication
// using Orjnz.IdentityProvider.Web.Data;
// using System;
// using System.Collections.Generic;
// using System.Collections.Immutable;
// using System.Linq;
// using System.Text.Json;
// using System.Threading.Tasks;
// using static OpenIddict.Abstractions.OpenIddictConstants;

// namespace Orjnz.IdentityProvider.Web.Services
// {
//     public class ConsentService : IConsentService
//     {
//         private readonly IOpenIddictAuthorizationManager _authorizationManager;
//         private readonly IOpenIddictApplicationManager _applicationManager; // Used via IClientApplicationService now
//         private readonly IOpenIddictScopeManager _scopeManager;
//         private readonly IClientApplicationService _clientAppService; // Preferred way to get app details
//         private readonly UserManager<ApplicationUser> _userManager;
//         private readonly ILogger<ConsentService> _logger;

//         public ConsentService(
//             IOpenIddictAuthorizationManager authorizationManager,
//             IOpenIddictApplicationManager applicationManager, // Keep for direct use if needed
//             IOpenIddictScopeManager scopeManager,
//             IClientApplicationService clientAppService,
//             UserManager<ApplicationUser> userManager,
//             ILogger<ConsentService> logger)
//         {
//             _authorizationManager = authorizationManager;
//             _applicationManager = applicationManager;
//             _scopeManager = scopeManager;
//             _clientAppService = clientAppService;
//             _userManager = userManager;
//             _logger = logger;
//         }

//         public async Task<ConsentResult> CheckConsentAsync(
//             ApplicationUser user,
//             OpenIddictEntityFrameworkCoreApplication application,
//             ImmutableArray<string> requestedScopes,
//             OpenIddictRequest oidcRequest)
//         {
//             ArgumentNullException.ThrowIfNull(user);
//             ArgumentNullException.ThrowIfNull(application);
//             ArgumentNullException.ThrowIfNull(oidcRequest);

//             string userId = await _userManager.GetUserIdAsync(user);
//             string? applicationId = await _clientAppService.GetApplicationIdAsync(application);
//             if (applicationId == null)
//             {
//                 _logger.LogError("Application ID could not be retrieved for client {ClientId}", oidcRequest.ClientId);
//                 return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.ServerError, ErrorDescription: "Application details error.");
//             }

//             // Retrieve existing permanent authorizations for the user, client that match ALL currently requested scopes.
//             // This helps determine if consent for this specific set of scopes was already given.
//             var authorizationsFromDb = new List<OpenIddictEntityFrameworkCoreAuthorization>();
//             await foreach (var authObject in _authorizationManager.FindAsync(
//                 subject: userId,
//                 client : applicationId,
//                 status : Statuses.Valid,
//                 type   : AuthorizationTypes.Permanent,
//                 scopes : requestedScopes // Filter by currently requested scopes
//             ))
//             {
//                 if (authObject is OpenIddictEntityFrameworkCoreAuthorization concreteAuth)
//                 {
//                     authorizationsFromDb.Add(concreteAuth);
//                 }
//             }

//             string? applicationConsentType = await _clientAppService.GetApplicationConsentTypeAsync(application);

//             // Case 1: Implicit consent type for the application.
//             if (applicationConsentType == ConsentTypes.Implicit)
//             {
//                 _logger.LogInformation("Consent type is Implicit for client {ClientId}. Granting scopes.", oidcRequest.ClientId);
//                 return new ConsentResult(ConsentStatus.ConsentImplicitlyGranted, requestedScopes);
//             }

//             // Case 2: External consent type (e.g., admin pre-approved).
//             if (applicationConsentType == ConsentTypes.External)
//             {
//                 if (!authorizationsFromDb.Any())
//                 {
//                     _logger.LogWarning("External consent type for client {ClientId}, but no matching authorization found for user {UserId}.", oidcRequest.ClientId, userId);
//                     return new ConsentResult(ConsentStatus.ConsentDeniedByPolicy, ImmutableArray<string>.Empty, Error: Errors.ConsentRequired, ErrorDescription: "The logged in user is not allowed to access this client application.");
//                 }
//                 _logger.LogInformation("External consent type for client {ClientId} and existing authorization found. Granting scopes.", oidcRequest.ClientId);
//                 return new ConsentResult(ConsentStatus.ConsentGranted, requestedScopes); // Previously granted by admin
//             }

//             // Case 3: Explicit or Systematic consent types.
//             if (applicationConsentType == ConsentTypes.Explicit || applicationConsentType == ConsentTypes.Systematic)
//             {
//                 // If an authorization covering ALL requested scopes exists AND no explicit "prompt=consent" was made.
//                 if (authorizationsFromDb.Any() && !oidcRequest.HasPrompt(Prompts.Consent))
//                 {
//                     _logger.LogInformation("Explicit/Systematic consent type for client {ClientId}, existing authorization covers scopes, and no consent prompt. Granting scopes.", oidcRequest.ClientId);
//                     return new ConsentResult(ConsentStatus.ConsentGranted, requestedScopes); // Previously granted by user
//                 }

//                 // If prompt=none was specified, and we've reached here, it means consent is needed but cannot be interactively obtained.
//                 if (oidcRequest.HasPrompt(Prompts.None))
//                 {
//                     _logger.LogWarning("Explicit/Systematic consent required for client {ClientId} but prompt=none specified.", oidcRequest.ClientId);
//                     return new ConsentResult(ConsentStatus.ConsentDeniedByPolicy, ImmutableArray<string>.Empty, Error: Errors.ConsentRequired, ErrorDescription: "Interactive user consent is required.");
//                 }

//                 // Otherwise, user interaction (consent page) is required.
//                 _logger.LogInformation("Explicit/Systematic consent required for client {ClientId}. User interaction needed.", oidcRequest.ClientId);
//                 string? appDisplayName = await _applicationManager.GetDisplayNameAsync(application);
//                 return new ConsentResult(ConsentStatus.ConsentRequired, requestedScopes, ApplicationDisplayName: appDisplayName);
//             }

//             // Fallback: Should not be reached if consent types are comprehensive.
//             _logger.LogError("Unhandled consent scenario for client {ClientId} with consent type {ConsentType}.", oidcRequest.ClientId, applicationConsentType);
//             return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.ServerError, ErrorDescription: "Unsupported consent configuration.");
//         }


//         public IActionResult DisplayConsentPage(
//             PageModel pageModel,
//             OpenIddictRequest oidcRequest,
//             string applicationDisplayName,
//             ImmutableArray<string> scopesRequiringConsent,
//             string userId) // Pass userId for context on consent page
//         {
//             _logger.LogInformation("Redirecting to consent page for client displaying as {ApplicationDisplayName}, user {UserId}.", applicationDisplayName, userId);

//             // We'll create a proper ConsentViewModel later for the consent page.
//             // For now, just enough to redirect. The consent page will need to re-fetch request details.
//             // It's better to pass minimal, necessary, and safe data.
//             // The consent page will use the OIDC request (which OpenIddict makes available via GetOpenIddictServerRequest)
//             // and the application/user details.

//             // Construct the query string for the consent page
//             var queryParams = new Dictionary<string, string?>
//             {
//                 // Pass essential OIDC parameters that the consent page might need to reconstruct context
//                 // or to pass back to the Authorize endpoint upon submission.
//                 // The Authorize endpoint will re-validate everything.
//                 { "client_id", oidcRequest.ClientId },
//                 { "redirect_uri", oidcRequest.RedirectUri },
//                 { "response_type", oidcRequest.ResponseType },
//                 { "scope", oidcRequest.Scope }, // Original requested scope string
//                 { "state", oidcRequest.State },
//                 // Potentially nonce, code_challenge, code_challenge_method if needed by consent page post-back logic
//                 { "userId_for_consent", userId } // To identify the user on the consent page
//             };

//             // A better way for complex objects is to use TempData or a short-lived cache entry
//             // keyed by a temporary ID, then pass that ID. But for now, let's assume simple query params.
//             // However, the full oidcRequest object is too large for query string.
//             // The consent page should call HttpContext.GetOpenIddictServerRequest() itself.

//             return pageModel.RedirectToPage("/Connect/Consent", new { /* values for consent page */
//                 userId = userId, // So consent page knows which user
//                 clientId = oidcRequest.ClientId // So consent page knows which client
//                 // The consent page will then re-fetch the OpenIddictRequest using HttpContext
//             });
//         }

//         public async Task<ConsentResult> ProcessConsentSubmissionAsync(
//             ApplicationUser user,
//             OpenIddictEntityFrameworkCoreApplication application,
//             ImmutableArray<string> submittedScopes, // Scopes user actually agreed to from the form
//             bool wasConsentGranted, // True if user clicked "Accept", false if "Deny"
//             OpenIddictRequest oidcRequest) // Original OIDC request for context
//         {
//             ArgumentNullException.ThrowIfNull(user);
//             ArgumentNullException.ThrowIfNull(application);
//             ArgumentNullException.ThrowIfNull(oidcRequest);

//             if (!wasConsentGranted)
//             {
//                 _logger.LogInformation("User {UserId} denied consent for client {ClientId}.", user.Id, oidcRequest.ClientId);
//                 return new ConsentResult(ConsentStatus.ConsentDeniedByUser, ImmutableArray<string>.Empty, Error: Errors.AccessDenied, ErrorDescription: "The resource owner or authorization server denied the request.");
//             }

//             // Validate that submittedScopes are a subset of originally requested scopes and are valid for the client.
//             // This step is crucial to prevent privilege escalation via consent form tampering.
//             // The IScopeValidationService could be enhanced or reused here.
//             var requestedScopes = oidcRequest.GetScopes();
//             if (!submittedScopes.All(ss => requestedScopes.Contains(ss)))
//             {
//                 _logger.LogError("Consent submission for user {UserId}, client {ClientId} contained scopes not originally requested.", user.Id, oidcRequest.ClientId);
//                 return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.InvalidScope, ErrorDescription: "Invalid scopes submitted during consent.");
//             }

//             // Further validation with client permissions (could use IScopeValidationService)
//             var clientPermissions = await _clientAppService.GetClientPermissionsAsync(application);
//             var allSystemScopeEntities = new List<OpenIddictEntityFrameworkCoreScope>();
//             await foreach (var scopeObject in _scopeManager.ListAsync())
//             {
//                 if (scopeObject is OpenIddictEntityFrameworkCoreScope concreteScope) { allSystemScopeEntities.Add(concreteScope); }
//             }
//             var allSystemScopeNames = allSystemScopeEntities.Select(s => s.Name).Where(name => name != null).Select(name => name!).ToHashSet();

//             var finalValidatedSubmittedScopes = new HashSet<string>();
//             foreach (var submittedScope in submittedScopes)
//             {
//                  if ((allSystemScopeNames.Contains(submittedScope) &&
//                      clientPermissions.Any(p => p.StartsWith(Permissions.Prefixes.Scope + submittedScope))) ||
//                     submittedScope == Scopes.OpenId || submittedScope == Scopes.OfflineAccess) // Always allow these if client asks
//                 {
//                     finalValidatedSubmittedScopes.Add(submittedScope);
//                 }
//             }

//             if (!finalValidatedSubmittedScopes.Any() && submittedScopes.Any()) // If they submitted scopes but none were valid
//             {
//                  _logger.LogWarning("User {UserId} submitted scopes for client {ClientId}, but none were valid after validation.", user.Id, oidcRequest.ClientId);
//                 return new ConsentResult(ConsentStatus.Error, ImmutableArray<string>.Empty, Error: Errors.InvalidScope, ErrorDescription: "No valid scopes were granted.");
//             }


//             _logger.LogInformation("User {UserId} granted consent for scopes [{GrantedScopes}] for client {ClientId}.", user.Id, string.Join(", ", finalValidatedSubmittedScopes), oidcRequest.ClientId);
//             return new ConsentResult(ConsentStatus.ConsentGranted, finalValidatedSubmittedScopes.ToImmutableArray());
//         }
//     }
// }