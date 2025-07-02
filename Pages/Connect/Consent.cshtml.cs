// File: Orjnz.IdentityProvider.Web/Pages/Connect/Consent.cshtml.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives; // For StringValues
using OpenIddict.Abstractions;
// Remove direct reference if AppCustomOpenIddictApplication is used consistently
// using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Server.AspNetCore; // For OpenIddictServerAspNetCoreDefaults
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using Orjnz.IdentityProvider.Web.Services;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading; // For CancellationToken
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Orjnz.IdentityProvider.Web.Pages.Connect
{
   [Authorize(AuthenticationSchemes = "Identity.Application")] // Ensure user is authenticated via cookie to see consent page
    public class ConsentModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager; // Still useful for GetLocalizedDisplayNameAsync etc.
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConsentService _consentService; // For processing consent logic
        private readonly IClaimsGenerationService _claimsGenerationService; // For building claims identity
        private readonly IAuthorizationPersistenceService _authPersistenceService; // For saving authorization
        private readonly IClientApplicationService _clientAppService; // To get our custom application type
        private readonly ILogger<ConsentModel> _logger;

        public ConsentModel(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            UserManager<ApplicationUser> userManager,
            IConsentService consentService,
            IClaimsGenerationService claimsGenerationService,
            IAuthorizationPersistenceService authPersistenceService,
            IClientApplicationService clientAppService, // Added
            ILogger<ConsentModel> logger)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
            _userManager = userManager;
            _consentService = consentService;
            _claimsGenerationService = claimsGenerationService;
            _authPersistenceService = authPersistenceService;
            _clientAppService = clientAppService; // Added
            _logger = logger;
        }

        // Properties to bind from query string on GET and from hidden form fields on POST
        [BindProperty(SupportsGet = true)] public string UserIdFromQuery { get; set; } = string.Empty;
        [BindProperty(SupportsGet = true)] public string ClientId { get; set; } = string.Empty;
        [BindProperty(SupportsGet = true)] public string? RedirectUri { get; set; }
        [BindProperty(SupportsGet = true)] public string? ResponseType { get; set; }
        [BindProperty(SupportsGet = true)] public string? OriginalScopeParameter { get; set; }
        [BindProperty(SupportsGet = true)] public string? State { get; set; }
        [BindProperty(SupportsGet = true)] public string? Nonce { get; set; }
        [BindProperty(SupportsGet = true)] public string? CodeChallenge { get; set; }
        [BindProperty(SupportsGet = true)] public string? CodeChallengeMethod { get; set; }
        [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }


        [BindProperty]
        public ConsentInputModel Input { get; set; } = new ConsentInputModel();

        public string ApplicationDisplayName { get; set; } = string.Empty;
        public List<ScopeViewModel> ScopesToDisplay { get; set; } = new List<ScopeViewModel>();

        [TempData]
        public string? StatusMessage { get; set; }


        public class ConsentInputModel
        {
            [Required]
            public string Button { get; set; } = string.Empty; // "accept" or "deny"
            public List<string> GrantedScopes { get; set; } = new List<string>();
        }

        public class ScopeViewModel
        {
            public string Value { get; set; } = string.Empty;
            public string DisplayName { get; set; } = string.Empty;
            public string? Description { get; set; }
            public bool Required { get; set; }
            public bool PreSelected { get; set; }
        }

        public async Task<IActionResult> OnGetAsync(
            string userId,
            string client_id,
            string? redirect_uri,
            string? response_type,
            [FromQuery(Name = "scope")] string? scopeFromQuery,
            string? state,
            string? nonce,
            string? code_challenge,
            string? code_challenge_method,
            string? returnUrl = null,
            CancellationToken cancellationToken = default) // Added CancellationToken
        {
            UserIdFromQuery = userId;
            ClientId = client_id;
            RedirectUri = redirect_uri;
            ResponseType = response_type;
            OriginalScopeParameter = scopeFromQuery;
            State = state;
            Nonce = nonce;
            CodeChallenge = code_challenge;
            CodeChallengeMethod = code_challenge_method;
            ReturnUrl = returnUrl;

            _logger.LogInformation("Consent OnGet: UserId={UserId}, ClientId={ClientId}, OriginalScopeParam={OriginalScope}", UserIdFromQuery, ClientId, OriginalScopeParameter);

            if (string.IsNullOrEmpty(ClientId) || string.IsNullOrEmpty(UserIdFromQuery))
            {
                _logger.LogError("Consent OnGet: Client ID or User ID is missing from query parameters.");
                StatusMessage = "Error: Client or user context is missing for consent.";
                return Page();
            }

            // Use IClientApplicationService to get the custom application type
            // TODO: Update IClientApplicationService.GetApplicationByClientIdAsync to accept CancellationToken
            var application = await _clientAppService.GetApplicationByClientIdAsync(ClientId);
            if (application == null)
            {
                _logger.LogError("Consent OnGet: Application not found for ClientId: {ClientId}", ClientId);
                StatusMessage = "Error: Invalid client application for consent.";
                return Page();
            }
            // GetLocalizedDisplayNameAsync can take the base OpenIddictApplication type, or you can pass `application` directly
            ApplicationDisplayName = await _applicationManager.GetLocalizedDisplayNameAsync(application, cancellationToken) ?? ClientId;

            var requestedScopes = OriginalScopeParameter?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToImmutableArray()
                                     ?? ImmutableArray<string>.Empty;

            foreach (var scopeName in requestedScopes)
            {
                // TODO: Update IOpenIddictScopeManager methods (FindByNameAsync, GetLocalizedDisplayNameAsync, etc.)
                // in your service wrappers or ensure they accept CancellationToken if used directly.
                var scopeEntityObject = await _scopeManager.FindByNameAsync(scopeName, cancellationToken);
                if (scopeEntityObject != null) // Check if object is not null before trying to get properties
                {
                    ScopesToDisplay.Add(new ScopeViewModel
                    {
                        Value = scopeName,
                        DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(scopeEntityObject, cancellationToken) ?? scopeName,
                        Description = await _scopeManager.GetLocalizedDescriptionAsync(scopeEntityObject, cancellationToken),
                        Required = scopeName == Scopes.OpenId, // OpenId is typically required implicitly if requested
                        PreSelected = true // By default, pre-select all requested scopes
                    });
                }
                else { _logger.LogWarning("Consent OnGet: Scope {ScopeName} (requested by {ClientId}) not found.", scopeName, ClientId); }
            }

            if (!ScopesToDisplay.Any() && requestedScopes.Contains(Scopes.OpenId))
            {
                // Ensure openid is listed if it was the only one requested and somehow missed above
                ScopesToDisplay.Add(new ScopeViewModel { Value = Scopes.OpenId, DisplayName = "Basic sign-in information", Required = true, PreSelected = true });
            }
            else if (!ScopesToDisplay.Any())
            {
                 _logger.LogWarning("Consent OnGet: No valid/displayable scopes for ClientId {ClientId}.", ClientId);
                 StatusMessage = "Error: No valid permissions to consent to for this application.";
                 return Page();
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default) // Added CancellationToken
        {
            _logger.LogInformation("Consent OnPost: UserId={BoundUserId}, ClientId={BoundClientId}, Button={ButtonAction}", UserIdFromQuery, ClientId, Input.Button);

            if (string.IsNullOrEmpty(UserIdFromQuery) || string.IsNullOrEmpty(ClientId))
            {
                _logger.LogError("Consent OnPost: UserId or ClientId is missing from bound model properties.");
                StatusMessage = "Error: Critical session information is missing. Please try again.";
                return Page();
            }

            var user = await _userManager.GetUserAsync(User); // This is okay, not directly I/O bound for this call
            if (user == null || user.Id != UserIdFromQuery)
            {
                _logger.LogWarning("Consent OnPost: Authenticated user mismatch or not found. Forcing re-authentication.");
                return Challenge(IdentityConstants.ApplicationScheme);
            }

            // Use IClientApplicationService
            // TODO: Update IClientApplicationService.GetApplicationByClientIdAsync to accept CancellationToken
            var application = await _clientAppService.GetApplicationByClientIdAsync(ClientId);
            if (application == null)
            {
                _logger.LogError("Consent OnPost: Application {ClientId} not found.", ClientId);
                StatusMessage = "Error: Client application not found.";
                return Page();
            }

            var oidcParamsList = new List<KeyValuePair<string, StringValues>>();
            if (!string.IsNullOrEmpty(ClientId)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.ClientId, ClientId));
            if (!string.IsNullOrEmpty(RedirectUri)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.RedirectUri, RedirectUri));
            if (!string.IsNullOrEmpty(ResponseType)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.ResponseType, ResponseType));
            if (!string.IsNullOrEmpty(OriginalScopeParameter)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.Scope, OriginalScopeParameter));
            if (!string.IsNullOrEmpty(State)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.State, State));
            if (!string.IsNullOrEmpty(Nonce)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.Nonce, Nonce));
            if (!string.IsNullOrEmpty(CodeChallenge)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.CodeChallenge, CodeChallenge));
            if (!string.IsNullOrEmpty(CodeChallengeMethod)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.CodeChallengeMethod, CodeChallengeMethod));
            
            var reconstructedOidcRequest = new OpenIddictRequest(oidcParamsList);

            // TODO: Update IConsentService.ProcessConsentSubmissionAsync to accept CancellationToken
            var consentProcessingResult = await _consentService.ProcessConsentSubmissionAsync(
                user,
                application, // Pass AppCustomOpenIddictApplication
                Input.GrantedScopes?.ToImmutableArray() ?? ImmutableArray<string>.Empty,
                Input.Button == "accept",
                reconstructedOidcRequest
                // cancellationToken (if service method is updated)
            );

            if (consentProcessingResult.Status == ConsentStatus.ConsentDeniedByUser || 
                consentProcessingResult.Status == ConsentStatus.ConsentDeniedByPolicy)
            {
                _logger.LogInformation("Consent explicitly denied by user or policy for ClientId {ClientId}. Error: {Error}", ClientId, consentProcessingResult.ErrorDescription);
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = consentProcessingResult.Error ?? Errors.AccessDenied,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = consentProcessingResult.ErrorDescription ?? "The authorization was denied."
                    }));
            }

            if (consentProcessingResult.Status == ConsentStatus.Error || !consentProcessingResult.GrantedScopes.Any())
            {
                 _logger.LogWarning("Consent processing error or no scopes granted for ClientId {ClientId}: {ErrorDescription}", ClientId, consentProcessingResult.ErrorDescription);
                 StatusMessage = consentProcessingResult.ErrorDescription ?? "An error occurred, or no permissions were granted. Please try again.";
                 await RepopulatePageModelForErrorAsync(application, cancellationToken); // Pass CT
                 return Page();
            }

            _logger.LogInformation("Consent accepted by user {UserId} for client {ClientId}. Granted scopes: [{GrantedScopes}]", user.Id, ClientId, string.Join(", ", consentProcessingResult.GrantedScopes));

            // --- UPDATED CALL ---
            var claimsIdentity = await _claimsGenerationService.BuildUserClaimsIdentityAsync(
                user,
                application, // Pass AppCustomOpenIddictApplication
                consentProcessingResult.GrantedScopes,
                reconstructedOidcRequest,
                cancellationToken); // Pass the CancellationToken
            // --- END UPDATED CALL ---

            var principalToSignIn = new ClaimsPrincipal(claimsIdentity);

            // TODO: Update IAuthorizationPersistenceService.EnsureAuthorizationAsync to accept CancellationToken
            var authorizationEntity = await _authPersistenceService.EnsureAuthorizationAsync(
                principalToSignIn, user, application /*, cancellationToken */);

            if (authorizationEntity == null) {
                 _logger.LogError("Failed to ensure authorization persistence after consent for user {UserId}, ClientId {ClientId}", user.Id, ClientId);
                 StatusMessage = "Error: Could not save your consent. Please try again.";
                 await RepopulatePageModelForErrorAsync(application, cancellationToken); // Pass CT
                 return Page();
            }

            // TODO: Update IAuthorizationPersistenceService.GetAuthorizationIdAsync to accept CancellationToken
            var authorizationId = await _authPersistenceService.GetAuthorizationIdAsync(authorizationEntity! /*, cancellationToken */); // Non-null assertion if previous check passed
            if (string.IsNullOrEmpty(authorizationId)) {
                _logger.LogError("Failed to retrieve ID from persisted authorization after consent for user {UserId}, ClientId {ClientId}", user.Id, ClientId);
                StatusMessage = "Error: Could not link your consent. Please try again.";
                await RepopulatePageModelForErrorAsync(application, cancellationToken); // Pass CT
                return Page();
            }
            claimsIdentity.SetAuthorizationId(authorizationId);

            _logger.LogInformation("Redirecting back to /Connect/Authorize to finalize OIDC flow for user {UserId}, client {ClientId}", user.Id, ClientId);

            var authorizeRedirectParams = new Dictionary<string, string?>();
            authorizeRedirectParams[Parameters.ClientId] = ClientId;
            authorizeRedirectParams[Parameters.RedirectUri] = RedirectUri;
            authorizeRedirectParams[Parameters.ResponseType] = ResponseType;
            authorizeRedirectParams[Parameters.Scope] = OriginalScopeParameter;
            authorizeRedirectParams[Parameters.State] = State;
            authorizeRedirectParams[Parameters.Nonce] = Nonce;
            authorizeRedirectParams[Parameters.CodeChallenge] = CodeChallenge;
            authorizeRedirectParams[Parameters.CodeChallengeMethod] = CodeChallengeMethod;

            var nonNullAuthorizeRedirectParams = authorizeRedirectParams
                                                .Where(kvp => kvp.Value != null)
                                                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

            if (!nonNullAuthorizeRedirectParams.Any())
            {
                _logger.LogError("Cannot redirect to authorize endpoint: no parameters to build query string for user {UserId}, client {ClientId}", user.Id, ClientId);
                StatusMessage = "Error: Could not construct the final authorization redirect. Please try again.";
                await RepopulatePageModelForErrorAsync(application, cancellationToken);
                return Page();
            }

            var queryString = QueryString.Create(nonNullAuthorizeRedirectParams!);
            var authorizeUrl = Url.Page("/Connect/Authorize") + queryString.ToUriComponent();
            if (string.IsNullOrEmpty(authorizeUrl))
            {
                 _logger.LogError("Generated authorizeUrl is null or empty. Query: {QueryString}", queryString.ToUriComponent());
                 StatusMessage = "Error: Could not construct the final authorization redirect URL.";
                 await RepopulatePageModelForErrorAsync(application, cancellationToken);
                 return Page();
            }

            return Redirect(authorizeUrl!);
        }

        private async Task RepopulatePageModelForErrorAsync(AppCustomOpenIddictApplication application, CancellationToken cancellationToken) // Changed type, added CT
        {
            // Use _applicationManager or direct property from AppCustomOpenIddictApplication
            ApplicationDisplayName = await _applicationManager.GetLocalizedDisplayNameAsync(application, cancellationToken) ?? application.ClientId ?? ClientId;
            var requestedScopesFromParam = OriginalScopeParameter?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToImmutableArray() ?? ImmutableArray<string>.Empty;
            ScopesToDisplay.Clear();
            foreach (var scopeName in requestedScopesFromParam)
            {
                 var scopeEntityObject = await _scopeManager.FindByNameAsync(scopeName, cancellationToken);
                 if (scopeEntityObject != null)
                 {
                    ScopesToDisplay.Add(new ScopeViewModel
                    {
                        Value = scopeName,
                        DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(scopeEntityObject, cancellationToken) ?? scopeName,
                        Description = await _scopeManager.GetLocalizedDescriptionAsync(scopeEntityObject, cancellationToken),
                        Required = scopeName == Scopes.OpenId,
                        PreSelected = Input.GrantedScopes?.Contains(scopeName) ?? true
                    });
                 }
            }
             if (!ScopesToDisplay.Any() && requestedScopesFromParam.Contains(Scopes.OpenId))
            {
                ScopesToDisplay.Add(new ScopeViewModel { Value = Scopes.OpenId, DisplayName = "Basic sign-in information", Required = true, PreSelected = true });
            }
        }
    }
}
// // File: Orjnz.IdentityProvider.Web/Pages/Connect/Consent.cshtml.cs
// using Microsoft.AspNetCore.Authentication;
// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Identity;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.AspNetCore.Mvc.RazorPages;
// using Microsoft.Extensions.Logging;
// using Microsoft.Extensions.Primitives; // For StringValues
// using OpenIddict.Abstractions;
// using OpenIddict.EntityFrameworkCore.Models; // For OpenIddictEntityFrameworkCoreApplication
// using OpenIddict.Server.AspNetCore; // For OpenIddictServerAspNetCoreDefaults
// using Orjnz.IdentityProvider.Web.Data;
// using Orjnz.IdentityProvider.Web.Services;
// using System;
// using System.Collections.Generic;
// using System.Collections.Immutable;
// using System.ComponentModel.DataAnnotations;
// using System.Linq;
// using System.Security.Claims;
// using System.Threading.Tasks;
// using static OpenIddict.Abstractions.OpenIddictConstants; // For Errors, Prompts, Scopes, Parameters, etc.

// namespace Orjnz.IdentityProvider.Web.Pages.Connect
// {
//    [Authorize(AuthenticationSchemes = "Identity.Application")]
//     public class ConsentModel : PageModel
//     {
//         private readonly IOpenIddictApplicationManager _applicationManager;
//         private readonly IOpenIddictScopeManager _scopeManager;
//         private readonly UserManager<ApplicationUser> _userManager;
//         private readonly IConsentService _consentService;
//         private readonly IClaimsGenerationService _claimsGenerationService;
//         private readonly IAuthorizationPersistenceService _authPersistenceService;
//         private readonly ILogger<ConsentModel> _logger;

//         public ConsentModel(
//             IOpenIddictApplicationManager applicationManager,
//             IOpenIddictScopeManager scopeManager,
//             UserManager<ApplicationUser> userManager,
//             IConsentService consentService,
//             IClaimsGenerationService claimsGenerationService,
//             IAuthorizationPersistenceService authPersistenceService,
//             ILogger<ConsentModel> logger)
//         {
//             _applicationManager = applicationManager;
//             _scopeManager = scopeManager;
//             _userManager = userManager;
//             _consentService = consentService;
//             _claimsGenerationService = claimsGenerationService;
//             _authPersistenceService = authPersistenceService;
//             _logger = logger;
//         }

//         // Properties to bind from query string on GET and from hidden form fields on POST
//         [BindProperty(SupportsGet = true)] public string UserIdFromQuery { get; set; } = string.Empty; // Renamed to avoid clash if User.Id is used
//         [BindProperty(SupportsGet = true)] public string ClientId { get; set; } = string.Empty;
//         [BindProperty(SupportsGet = true)] public string? RedirectUri { get; set; }
//         [BindProperty(SupportsGet = true)] public string? ResponseType { get; set; }
//         [BindProperty(SupportsGet = true)] public string? OriginalScopeParameter { get; set; }
//         [BindProperty(SupportsGet = true)] public string? State { get; set; }
//         [BindProperty(SupportsGet = true)] public string? Nonce { get; set; }
//         [BindProperty(SupportsGet = true)] public string? CodeChallenge { get; set; }
//         [BindProperty(SupportsGet = true)] public string? CodeChallengeMethod { get; set; }
//         [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; } // For local redirects after completion


//         [BindProperty] // For the POSTed form data (button and checked scopes)
//         public ConsentInputModel Input { get; set; } = new ConsentInputModel();

//         // For display on the page (populated in OnGet)
//         public string ApplicationDisplayName { get; set; } = string.Empty;
//         public List<ScopeViewModel> ScopesToDisplay { get; set; } = new List<ScopeViewModel>();

//         [TempData]
//         public string? StatusMessage { get; set; }


//         public class ConsentInputModel
//         {
//             [Required]
//             public string Button { get; set; } = string.Empty; // "accept" or "deny"
//             public List<string> GrantedScopes { get; set; } = new List<string>();
//         }

//         public class ScopeViewModel
//         {
//             public string Value { get; set; } = string.Empty;
//             public string DisplayName { get; set; } = string.Empty;
//             public string? Description { get; set; }
//             public bool Required { get; set; }
//             public bool PreSelected { get; set; }
//         }

//         public async Task<IActionResult> OnGetAsync(
//             string userId, // Parameter from AuthorizeModel's redirect
//             string client_id, // Parameter from AuthorizeModel's redirect
//             string? redirect_uri,
//             string? response_type,
//             [FromQuery(Name = "scope")] string? scopeFromQuery, // Explicitly map 'scope' from query
//             string? state,
//             string? nonce,
//             string? code_challenge,
//             string? code_challenge_method,
//             string? returnUrl = null)
//         {
//             // Assign all bound properties from parameters received in the GET request
//             UserIdFromQuery = userId; // Using the renamed property
//             ClientId = client_id;
//             RedirectUri = redirect_uri;
//             ResponseType = response_type;
//             OriginalScopeParameter = scopeFromQuery;
//             State = state;
//             Nonce = nonce;
//             CodeChallenge = code_challenge;
//             CodeChallengeMethod = code_challenge_method;
//             ReturnUrl = returnUrl; // Capture if needed for local navigation, though OIDC state handles flow

//             _logger.LogInformation("Consent OnGet: UserId={UserId}, ClientId={ClientId}, OriginalScopeParam={OriginalScope}", UserIdFromQuery, ClientId, OriginalScopeParameter);

//             if (string.IsNullOrEmpty(ClientId) || string.IsNullOrEmpty(UserIdFromQuery))
//             {
//                 _logger.LogError("Consent OnGet: Client ID or User ID is missing from query parameters.");
//                 StatusMessage = "Error: Client or user context is missing for consent.";
//                 return Page(); // Show error on current page or redirect
//             }

//             var application = await _applicationManager.FindByClientIdAsync(ClientId) as OpenIddictEntityFrameworkCoreApplication;
//             if (application == null)
//             {
//                 _logger.LogError("Consent OnGet: Application not found for ClientId: {ClientId}", ClientId);
//                 StatusMessage = "Error: Invalid client application for consent.";
//                 return Page();
//             }
//             ApplicationDisplayName = await _applicationManager.GetLocalizedDisplayNameAsync(application) ?? ClientId;

//             var requestedScopes = OriginalScopeParameter?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToImmutableArray()
//                                      ?? ImmutableArray<string>.Empty;

//             foreach (var scopeName in requestedScopes)
//             {
//                 var scopeEntityObject = await _scopeManager.FindByNameAsync(scopeName);
//                 if (scopeEntityObject is OpenIddictEntityFrameworkCoreScope scopeEntity) // Ensure correct type
//                 {
//                     ScopesToDisplay.Add(new ScopeViewModel
//                     {
//                         Value = scopeName,
//                         DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(scopeEntity) ?? scopeName,
//                         Description = await _scopeManager.GetLocalizedDescriptionAsync(scopeEntity),
//                         Required = scopeName == Scopes.OpenId,
//                         PreSelected = true
//                     });
//                 }
//                 else { _logger.LogWarning("Consent OnGet: Scope {ScopeName} (requested by {ClientId}) not found or not of expected type.", scopeName, ClientId); }
//             }

//             if (!ScopesToDisplay.Any() && requestedScopes.Contains(Scopes.OpenId))
//             {
//                 ScopesToDisplay.Add(new ScopeViewModel { Value = Scopes.OpenId, DisplayName = "Basic sign-in information", Required = true, PreSelected = true });
//             }
//             else if (!ScopesToDisplay.Any())
//             {
//                  _logger.LogWarning("Consent OnGet: No valid/displayable scopes for ClientId {ClientId}.", ClientId);
//                  StatusMessage = "Error: No valid permissions to consent to for this application.";
//                  return Page();
//             }
//             return Page();
//         }

//         public async Task<IActionResult> OnPostAsync()
//         {
//             _logger.LogInformation("Consent OnPost: UserId={BoundUserId}, ClientId={BoundClientId}, Button={ButtonAction}", UserIdFromQuery, ClientId, Input.Button);

//             // Validate that essential bound properties (from hidden fields) are present
//             if (string.IsNullOrEmpty(UserIdFromQuery) || string.IsNullOrEmpty(ClientId))
//             {
//                 _logger.LogError("Consent OnPost: UserId or ClientId is missing from bound model properties. Form may be incomplete or tampered.");
//                 StatusMessage = "Error: Critical session information is missing. Please try the authorization process again from the client application.";
//                 return Page(); // Re-render page with error
//             }

//             var user = await _userManager.GetUserAsync(User); // Gets the currently cookie-authenticated user
//             if (user == null || user.Id != UserIdFromQuery) // Validate against bound UserIdFromQuery
//             {
//                 _logger.LogWarning("Consent OnPost: Authenticated user mismatch or not found. AuthUser: {AuthUserId}, BoundUserId: {BoundUserId}. Forcing re-authentication.", _userManager.GetUserId(User), UserIdFromQuery);
//                 return Challenge(IdentityConstants.ApplicationScheme);
//             }

//             var application = await _applicationManager.FindByClientIdAsync(ClientId) as OpenIddictEntityFrameworkCoreApplication;
//             if (application == null)
//             {
//                 _logger.LogError("Consent OnPost: Application {ClientId} not found.", ClientId);
//                 StatusMessage = "Error: Client application not found.";
//                 return Page();
//             }

//             // Reconstruct the OIDC request parameters for services
//             // Use IEnumerable<KeyValuePair<string, StringValues>> for OpenIddictRequest constructor
//             var oidcParamsList = new List<KeyValuePair<string, StringValues>>();
//             if (!string.IsNullOrEmpty(ClientId)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.ClientId, ClientId));
//             if (!string.IsNullOrEmpty(RedirectUri)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.RedirectUri, RedirectUri));
//             if (!string.IsNullOrEmpty(ResponseType)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.ResponseType, ResponseType));
//             if (!string.IsNullOrEmpty(OriginalScopeParameter)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.Scope, OriginalScopeParameter));
//             if (!string.IsNullOrEmpty(State)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.State, State));
//             if (!string.IsNullOrEmpty(Nonce)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.Nonce, Nonce));
//             if (!string.IsNullOrEmpty(CodeChallenge)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.CodeChallenge, CodeChallenge));
//             if (!string.IsNullOrEmpty(CodeChallengeMethod)) oidcParamsList.Add(new KeyValuePair<string, StringValues>(Parameters.CodeChallengeMethod, CodeChallengeMethod));
            
//             var reconstructedOidcRequest = new OpenIddictRequest(oidcParamsList);


//             var consentProcessingResult = await _consentService.ProcessConsentSubmissionAsync(
//                 user,
//                 application,
//                 Input.GrantedScopes?.ToImmutableArray() ?? ImmutableArray<string>.Empty,
//                 Input.Button == "accept",
//                 reconstructedOidcRequest
//             );

//             if (consentProcessingResult.Status == ConsentStatus.ConsentDeniedByUser || 
//                 consentProcessingResult.Status == ConsentStatus.ConsentDeniedByPolicy)
//             {
//                 _logger.LogInformation("Consent explicitly denied by user or policy for ClientId {ClientId}. Error: {Error}", ClientId, consentProcessingResult.ErrorDescription);
//                 return Forbid(
//                     authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
//                     properties: new AuthenticationProperties(new Dictionary<string, string?>
//                     {
//                         [OpenIddictServerAspNetCoreConstants.Properties.Error] = consentProcessingResult.Error ?? Errors.AccessDenied,
//                         [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = consentProcessingResult.ErrorDescription ?? "The authorization was denied."
//                     }));
//             }

//             if (consentProcessingResult.Status == ConsentStatus.Error || !consentProcessingResult.GrantedScopes.Any())
//             {
//                  _logger.LogWarning("Consent processing error or no scopes granted for ClientId {ClientId}: {ErrorDescription}", ClientId, consentProcessingResult.ErrorDescription);
//                  StatusMessage = consentProcessingResult.ErrorDescription ?? "An error occurred, or no permissions were granted. Please try again.";
//                  // Repopulate necessary data for re-displaying the form
//                  await RepopulatePageModelForErrorAsync(application);
//                  return Page();
//             }

//             _logger.LogInformation("Consent accepted by user {UserId} for client {ClientId}. Granted scopes: [{GrantedScopes}]", user.Id, ClientId, string.Join(", ", consentProcessingResult.GrantedScopes));

//             var claimsIdentity = await _claimsGenerationService.BuildUserClaimsIdentityAsync(
//                 user, application,
//                 consentProcessingResult.GrantedScopes, // Use scopes from consent result
//                 reconstructedOidcRequest // Pass the reconstructed OIDC request
//             );
//             var principalToSignIn = new ClaimsPrincipal(claimsIdentity);

//             var authorizationEntity = await _authPersistenceService.EnsureAuthorizationAsync(
//                 principalToSignIn, user, application);

//             if (authorizationEntity == null) {
//                  _logger.LogError("Failed to ensure authorization persistence after consent for user {UserId}, ClientId {ClientId}", user.Id, ClientId);
//                  StatusMessage = "Error: Could not save your consent. Please try again.";
//                  await RepopulatePageModelForErrorAsync(application);
//                  return Page();
//             }

//             var authorizationId = await _authPersistenceService.GetAuthorizationIdAsync(authorizationEntity);
//             if (string.IsNullOrEmpty(authorizationId)) {
//                 _logger.LogError("Failed to retrieve ID from persisted authorization after consent for user {UserId}, ClientId {ClientId}", user.Id, ClientId);
//                 StatusMessage = "Error: Could not link your consent. Please try again.";
//                 await RepopulatePageModelForErrorAsync(application);
//                 return Page();
//             }
//             claimsIdentity.SetAuthorizationId(authorizationId);

//             // Redirect back to the Authorize endpoint to finalize OIDC flow
//             _logger.LogInformation("Redirecting back to /Connect/Authorize to finalize OIDC flow for user {UserId}, client {ClientId}", user.Id, ClientId);

//             var authorizeRedirectParams = new Dictionary<string, string?>();

//             // Populate from the reconstructedOidcRequest or the original bound properties
//             // Using original bound properties is safer as they are directly from the GET/form.
//             authorizeRedirectParams[Parameters.ClientId] = ClientId; // From [BindProperty(SupportsGet = true)]
//             authorizeRedirectParams[Parameters.RedirectUri] = RedirectUri;
//             authorizeRedirectParams[Parameters.ResponseType] = ResponseType;
//             authorizeRedirectParams[Parameters.Scope] = OriginalScopeParameter; // Original scope string
//             authorizeRedirectParams[Parameters.State] = State;
//             authorizeRedirectParams[Parameters.Nonce] = Nonce;
//             authorizeRedirectParams[Parameters.CodeChallenge] = CodeChallenge;
//             authorizeRedirectParams[Parameters.CodeChallengeMethod] = CodeChallengeMethod;
//             // Add any other custom or standard OIDC parameters that were part of the original authorize request
//             // and were passed to this consent page.

//             // Filter out null values before creating query string
//             var nonNullAuthorizeRedirectParams = authorizeRedirectParams
//                                                 .Where(kvp => kvp.Value != null)
//                                                 .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

//             if (!nonNullAuthorizeRedirectParams.Any())
//             {
//                 _logger.LogError("Cannot redirect to authorize endpoint: no parameters to build query string for user {UserId}, client {ClientId}", user.Id, ClientId);
//                 StatusMessage = "Error: Could not construct the final authorization redirect. Please try again.";
//                 await RepopulatePageModelForErrorAsync(application); // Make sure application is in scope
//                 return Page();
//             }

//             var queryString = QueryString.Create(nonNullAuthorizeRedirectParams!);
//             var authorizeUrl = Url.Page("/Connect/Authorize") + queryString.ToUriComponent(); // Use Url.Page to correctly generate URL to another Razor Page
//             if (string.IsNullOrEmpty(authorizeUrl))
//             {
//                  _logger.LogError("Generated authorizeUrl is null or empty. Query: {QueryString}", queryString.ToUriComponent());
//                  StatusMessage = "Error: Could not construct the final authorization redirect URL.";
//                  await RepopulatePageModelForErrorAsync(application);
//                  return Page();
//             }

//             return Redirect(authorizeUrl!);
//         }

//         private async Task RepopulatePageModelForErrorAsync(OpenIddictEntityFrameworkCoreApplication application)
//         {
//             ApplicationDisplayName = await _applicationManager.GetLocalizedDisplayNameAsync(application) ?? ClientId;
//             var requestedScopesFromParam = OriginalScopeParameter?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToImmutableArray() ?? ImmutableArray<string>.Empty;
//             ScopesToDisplay.Clear();
//             foreach (var scopeName in requestedScopesFromParam)
//             {
//                  var scopeEntityObject = await _scopeManager.FindByNameAsync(scopeName);
//                  if (scopeEntityObject is OpenIddictEntityFrameworkCoreScope scopeEntity)
//                  {
//                     ScopesToDisplay.Add(new ScopeViewModel
//                     {
//                         Value = scopeName,
//                         DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(scopeEntity) ?? scopeName,
//                         Description = await _scopeManager.GetLocalizedDescriptionAsync(scopeEntity),
//                         Required = scopeName == Scopes.OpenId,
//                         PreSelected = Input.GrantedScopes?.Contains(scopeName) ?? true // Re-check based on user's last attempt
//                     });
//                  }
//             }
//              if (!ScopesToDisplay.Any() && requestedScopesFromParam.Contains(Scopes.OpenId))
//             {
//                 ScopesToDisplay.Add(new ScopeViewModel { Value = Scopes.OpenId, DisplayName = "Basic sign-in information", Required = true, PreSelected = true });
//             }
//         }
//     }
// }
// // // File: Orjnz.IdentityProvider.Web/Pages/Connect/Consent.cshtml.cs
// // using Microsoft.AspNetCore; // For HttpContext if needed for other reasons, but not for GetOpenIddictServerRequest here
// // using Microsoft.AspNetCore.Authorization;
// // using Microsoft.AspNetCore.Identity;
// // using Microsoft.AspNetCore.Mvc;
// // using Microsoft.AspNetCore.Mvc.RazorPages;
// // using Microsoft.Extensions.Logging;
// // using OpenIddict.Abstractions;
// // using OpenIddict.Server.AspNetCore;
// // using OpenIddict.EntityFrameworkCore.Models;
// // using Orjnz.IdentityProvider.Web.Data;
// // using Orjnz.IdentityProvider.Web.Services;
// // using System;
// // using System.Collections.Generic;
// // using System.Collections.Immutable;
// // using System.ComponentModel.DataAnnotations;
// // using System.Linq;
// // using System.Security.Claims;
// // using System.Threading.Tasks;
// // using static OpenIddict.Abstractions.OpenIddictConstants;
// // using Microsoft.AspNetCore.Authentication;
// // using Microsoft.Extensions.Primitives;

// // namespace Orjnz.IdentityProvider.Web.Pages.Connect
// // {
// //     // [Authorize(AuthenticationSchemes = IdentityConstants.ApplicationScheme)]
// //     [Authorize(AuthenticationSchemes = "Identity.Application")] 
// //     public class ConsentModel : PageModel
// //     {
// //         private readonly IOpenIddictApplicationManager _applicationManager;
// //         private readonly IOpenIddictScopeManager _scopeManager;
// //         private readonly UserManager<ApplicationUser> _userManager;
// //         private readonly IConsentService _consentService;
// //         private readonly IClaimsGenerationService _claimsGenerationService;
// //         private readonly IAuthorizationPersistenceService _authPersistenceService;
// //         private readonly ILogger<ConsentModel> _logger;

// //         public ConsentModel(
// //             IOpenIddictApplicationManager applicationManager,
// //             IOpenIddictScopeManager scopeManager,
// //             UserManager<ApplicationUser> userManager,
// //             IConsentService consentService,
// //             IClaimsGenerationService claimsGenerationService,
// //             IAuthorizationPersistenceService authPersistenceService,
// //             ILogger<ConsentModel> logger)
// //         {
// //             _applicationManager = applicationManager;
// //             _scopeManager = scopeManager;
// //             _userManager = userManager;
// //             _consentService = consentService;
// //             _claimsGenerationService = claimsGenerationService;
// //             _authPersistenceService = authPersistenceService;
// //             _logger = logger;
// //         }

// //         // Properties to bind from query string on GET and to be used by the view for hidden fields
// //         [BindProperty(SupportsGet = true)] public string UserId { get; set; } = string.Empty;
// //         [BindProperty(SupportsGet = true)] public string ClientId { get; set; } = string.Empty;
// //         [BindProperty(SupportsGet = true)] public string? RedirectUri { get; set; }
// //         [BindProperty(SupportsGet = true)] public string? ResponseType { get; set; }
// //         [BindProperty(SupportsGet = true)] public string? OriginalScopeParameter { get; set; } // Stores the original 'scope' string
// //         [BindProperty(SupportsGet = true)] public string? State { get; set; }
// //         [BindProperty(SupportsGet = true)] public string? Nonce { get; set; }
// //         [BindProperty(SupportsGet = true)] public string? CodeChallenge { get; set; }
// //         [BindProperty(SupportsGet = true)] public string? CodeChallengeMethod { get; set; }

// //         [BindProperty] // For the POSTed form data
// //         public ConsentInputModel Input { get; set; } = new ConsentInputModel();

// //         // For display on the page
// //         public string ApplicationDisplayName { get; set; } = string.Empty;
// //         public List<ScopeViewModel> ScopesToDisplay { get; set; } = new List<ScopeViewModel>();

// //         public class ConsentInputModel
// //         {
// //             [Required]
// //             public string Button { get; set; } = string.Empty; // "accept" or "deny"
// //             public List<string> GrantedScopes { get; set; } = new List<string>();
// //         }

// //         public class ScopeViewModel
// //         {
// //             public string Value { get; set; } = string.Empty;
// //             public string DisplayName { get; set; } = string.Empty;
// //             public string? Description { get; set; }
// //             public bool Required { get; set; }
// //             public bool PreSelected { get; set; }
// //         }

// //         public async Task<IActionResult> OnGetAsync(
// //             string userId, string client_id, string? redirect_uri, string? response_type,
// //             [FromQuery(Name = "scope")] string? scopeFromQuery, // Explicitly map 'scope' from query
// //             string? state, string? nonce, string? code_challenge, string? code_challenge_method)
// //         {
// //             // Assign ALL bound properties from parameters
// //             UserId = userId;
// //             ClientId = client_id;
// //             RedirectUri = redirect_uri;
// //             ResponseType = response_type;
// //             OriginalScopeParameter = scopeFromQuery; // Use the value from query string
// //             State = state;
// //             Nonce = nonce;
// //             CodeChallenge = code_challenge;
// //             CodeChallengeMethod = code_challenge_method;

// //             _logger.LogInformation("Consent OnGet: UserId={UserId}, ClientId={ClientId}, ScopeParam={OriginalScope}", UserId, ClientId, OriginalScopeParameter);

// //             if (string.IsNullOrEmpty(ClientId) || string.IsNullOrEmpty(UserId))
// //             {
// //                 _logger.LogError("Consent OnGet: Client ID or User ID is missing. ClientId: {BoundClientId}, UserId: {BoundUserId}", ClientId, UserId);
// //                 return RedirectToPage("/Error", new { ErrorMessage = "Client or user context is missing for consent." });
// //             }

// //             var application = await _applicationManager.FindByClientIdAsync(ClientId) as OpenIddictEntityFrameworkCoreApplication;
// //             if (application == null)
// //             {
// //                 _logger.LogError("Consent OnGet: Application not found for ClientId: {ClientId}", ClientId);
// //                 return RedirectToPage("/Error", new { ErrorMessage = "Invalid client application for consent." });
// //             }
// //             ApplicationDisplayName = await _applicationManager.GetLocalizedDisplayNameAsync(application) ?? ClientId;

// //             var requestedScopes = OriginalScopeParameter?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
// //                                      .ToImmutableArray() ?? ImmutableArray<string>.Empty;

// //             foreach (var scopeName in requestedScopes)
// //             {
// //                 var scopeEntity = await _scopeManager.FindByNameAsync(scopeName);
// //                 if (scopeEntity != null)
// //                 {
// //                     ScopesToDisplay.Add(new ScopeViewModel
// //                     {
// //                         Value = scopeName,
// //                         DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(scopeEntity) ?? scopeName,
// //                         Description = await _scopeManager.GetLocalizedDescriptionAsync(scopeEntity),
// //                         Required = scopeName == Scopes.OpenId,
// //                         PreSelected = true
// //                     });
// //                 }
// //                 else { _logger.LogWarning("Consent OnGet: Scope {ScopeName} not defined.", scopeName); }
// //             }

// //             if (!ScopesToDisplay.Any() && requestedScopes.Contains(Scopes.OpenId))
// //             {
// //                 ScopesToDisplay.Add(new ScopeViewModel { Value = Scopes.OpenId, DisplayName = "Sign you in (OpenID Connect)", Required = true, PreSelected = true });
// //             }
// //             else if (!ScopesToDisplay.Any())
// //             {
// //                  _logger.LogWarning("Consent OnGet: No valid scopes to display for ClientId {ClientId}.", ClientId);
// //                  return RedirectToPage("/Error", new { ErrorMessage = "No valid scopes to consent to for this application." });
// //             }
// //             return Page();
// //         }

// //        public async Task<IActionResult> OnPostAsync()
// //         {
// //             _logger.LogInformation("Consent OnPost: UserId={UserId}, ClientId={ClientId}, Button={Button}", UserId, ClientId, Input.Button);

// //             if (string.IsNullOrEmpty(UserId) || string.IsNullOrEmpty(ClientId))
// //             {
// //                 _logger.LogError("Consent OnPost: UserId or ClientId is missing from bound properties.");
// //                 return RedirectToPage("/Error", new { ErrorMessage = "Session information incomplete. Please try again." });
// //             }

// //             var user = await _userManager.GetUserAsync(User);
// //             if (user == null || user.Id != UserId)
// //             {
// //                 _logger.LogWarning("Consent OnPost: User mismatch or not found. Authenticated User: {AuthUserId}, Bound UserId: {BoundUserId}. Forcing re-authentication.", _userManager.GetUserId(User), UserId);
// //                 return Challenge(IdentityConstants.ApplicationScheme);
// //             }

// //             var application = await _applicationManager.FindByClientIdAsync(ClientId) as OpenIddictEntityFrameworkCoreApplication;
// //             if (application == null)
// //             {
// //                 _logger.LogError("Consent OnPost: Application {ClientId} not found.", ClientId);
// //                 return RedirectToPage("/Error", new { ErrorMessage = "Client application not found." });
// //             }

// //             // --- Create OpenIddictRequest using Dictionary approach ---
// //             // Option 1: Using Dictionary<string, StringValues> (most compatible)
// //             var parameters = new Dictionary<string, StringValues>();
// //             if (!string.IsNullOrEmpty(ClientId)) parameters[Parameters.ClientId] = ClientId;
// //             if (!string.IsNullOrEmpty(RedirectUri)) parameters[Parameters.RedirectUri] = RedirectUri;
// //             if (!string.IsNullOrEmpty(ResponseType)) parameters[Parameters.ResponseType] = ResponseType;
// //             if (!string.IsNullOrEmpty(OriginalScopeParameter)) parameters[Parameters.Scope] = OriginalScopeParameter;
// //             if (!string.IsNullOrEmpty(State)) parameters[Parameters.State] = State;
// //             if (!string.IsNullOrEmpty(Nonce)) parameters[Parameters.Nonce] = Nonce;
// //             if (!string.IsNullOrEmpty(CodeChallenge)) parameters[Parameters.CodeChallenge] = CodeChallenge;
// //             if (!string.IsNullOrEmpty(CodeChallengeMethod)) parameters[Parameters.CodeChallengeMethod] = CodeChallengeMethod;

// //             // Create OpenIddictRequest - this should work with most OpenIddict versions
// //             var reconstructedOidcRequest = new OpenIddictRequest(parameters);

// //             // Alternative approach if the above doesn't work:
// //             // Create an empty OpenIddictRequest and set properties directly
// //             /*
// //             var reconstructedOidcRequest = new OpenIddictRequest();
// //             if (!string.IsNullOrEmpty(ClientId)) reconstructedOidcRequest.ClientId = ClientId;
// //             if (!string.IsNullOrEmpty(RedirectUri)) reconstructedOidcRequest.RedirectUri = RedirectUri;
// //             if (!string.IsNullOrEmpty(ResponseType)) reconstructedOidcRequest.ResponseType = ResponseType;
// //             if (!string.IsNullOrEmpty(OriginalScopeParameter)) reconstructedOidcRequest.Scope = OriginalScopeParameter;
// //             if (!string.IsNullOrEmpty(State)) reconstructedOidcRequest.State = State;
// //             if (!string.IsNullOrEmpty(Nonce)) reconstructedOidcRequest.Nonce = Nonce;
// //             if (!string.IsNullOrEmpty(CodeChallenge)) reconstructedOidcRequest.CodeChallenge = CodeChallenge;
// //             if (!string.IsNullOrEmpty(CodeChallengeMethod)) reconstructedOidcRequest.CodeChallengeMethod = CodeChallengeMethod;
// //             */

// //             // Process consent using the IConsentService
// //             var consentResult = await _consentService.ProcessConsentSubmissionAsync(
// //                 user,
// //                 application,
// //                 Input.GrantedScopes?.ToImmutableArray() ?? ImmutableArray<string>.Empty,
// //                 Input.Button == "accept",
// //                 reconstructedOidcRequest // Pass the reconstructed OIDC request
// //             );

// //             if (consentResult.Status == ConsentStatus.ConsentDeniedByUser || 
// //                 consentResult.Status == ConsentStatus.ConsentDeniedByPolicy)
// //             {
// //                 // ... (handle denial as before) ...
// //                 _logger.LogInformation("Consent denied by user/policy: {Error}", consentResult.ErrorDescription);
// //                 return Forbid(
// //                     authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
// //                     properties: new AuthenticationProperties(new Dictionary<string, string?>
// //                     {
// //                         [OpenIddictServerAspNetCoreConstants.Properties.Error] = consentResult.Error ?? Errors.AccessDenied,
// //                         [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = consentResult.ErrorDescription ?? "The authorization was denied."
// //                     }));
// //             }

// //             if (consentResult.Status == ConsentStatus.Error || !consentResult.GrantedScopes.Any())
// //             {
// //                  _logger.LogWarning("Consent processing error or no scopes granted: {Error}", consentResult.ErrorDescription);
// //                  ModelState.AddModelError(string.Empty, consentResult.ErrorDescription ?? "An error occurred or no permissions were granted.");
// //                  // Repopulate for view
// //                  ApplicationDisplayName = await _applicationManager.GetLocalizedDisplayNameAsync(application) ?? ClientId;
// //                  var requestedScopesFromParam = OriginalScopeParameter?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToImmutableArray() ?? ImmutableArray<string>.Empty;
// //                  foreach (var scopeName in requestedScopesFromParam) { /* repopulate ScopesToDisplay */ }
// //                  return Page();
// //             }

// //             _logger.LogInformation("Consent accepted. Granted scopes: [{GrantedScopes}]", string.Join(", ", consentResult.GrantedScopes));

// //             var claimsIdentity = await _claimsGenerationService.BuildUserClaimsIdentityAsync(
// //                 user, application, consentResult.GrantedScopes, reconstructedOidcRequest);
// //             var principalToSignIn = new ClaimsPrincipal(claimsIdentity);

// //             var authorizationEntity = await _authPersistenceService.EnsureAuthorizationAsync(
// //                 principalToSignIn, user, application);

// //             if (authorizationEntity == null) { /* Error */ return RedirectToPage("/Error"); }

// //             var authorizationId = await _authPersistenceService.GetAuthorizationIdAsync(authorizationEntity);
// //             if (string.IsNullOrEmpty(authorizationId)) { /* Error */ return RedirectToPage("/Error"); }
// //             claimsIdentity.SetAuthorizationId(authorizationId);

// //             _logger.LogInformation("Proceeding to sign in user {UserId} for client {ClientId} after consent.", user.Id, ClientId);
// //             return SignIn(principalToSignIn, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
// //         }
// //     }
// // }