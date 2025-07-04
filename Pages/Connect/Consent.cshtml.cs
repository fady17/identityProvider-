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
   /// <summary>
   /// This Razor Page model handles the user consent screen. It is displayed when a user
   /// needs to explicitly grant a client application permission to access certain scopes (data and actions).
   /// The user must be authenticated to view this page.
   /// </summary>
   [Authorize(AuthenticationSchemes = "Identity.Application")]
    public class ConsentModel : PageModel
    {
        // --- Injected Services ---
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConsentService _consentService;
        private readonly IClaimsGenerationService _claimsGenerationService;
        private readonly IAuthorizationPersistenceService _authPersistenceService;
        private readonly IClientApplicationService _clientAppService;
        private readonly ILogger<ConsentModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="ConsentModel"/> class.
        /// </summary>
        public ConsentModel(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            UserManager<ApplicationUser> userManager,
            IConsentService consentService,
            IClaimsGenerationService claimsGenerationService,
            IAuthorizationPersistenceService authPersistenceService,
            IClientApplicationService clientAppService,
            ILogger<ConsentModel> logger)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
            _userManager = userManager;
            _consentService = consentService;
            _claimsGenerationService = claimsGenerationService;
            _authPersistenceService = authPersistenceService;
            _clientAppService = clientAppService;
            _logger = logger;
        }

        // --- Bound Properties ---
        // These properties are bound from the query string on GET and from hidden form fields on POST
        // to reconstruct the original OIDC request context.
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

        /// <summary>
        /// Binds to the user's input from the consent form (which scopes were checked, and whether they accepted or denied).
        /// </summary>
        [BindProperty]
        public ConsentInputModel Input { get; set; } = new ConsentInputModel();
        
        // --- Page Display Properties ---
        public string ApplicationDisplayName { get; set; } = string.Empty;
        public List<ScopeViewModel> ScopesToDisplay { get; set; } = new List<ScopeViewModel>();

        [TempData]
        public string? StatusMessage { get; set; }

        /// <summary>
        /// Defines the data structure for the consent form input.
        /// </summary>
        public class ConsentInputModel
        {
            [Required]
            public string Button { get; set; } = string.Empty; // Holds the value of the button clicked ("accept" or "deny").
            public List<string> GrantedScopes { get; set; } = new List<string>(); // The list of scopes the user checked.
        }

        /// <summary>
        /// A view model representing a single scope to be displayed on the consent page.
        /// </summary>
        public class ScopeViewModel
        {
            public string Value { get; set; } = string.Empty; // The scope name (e.g., "profile").
            public string DisplayName { get; set; } = string.Empty; // The user-friendly name (e.g., "Profile Information").
            public string? Description { get; set; } // A description of what the scope allows.
            public bool Required { get; set; } // Whether the scope is mandatory (e.g., "openid").
            public bool PreSelected { get; set; } // Whether the checkbox for the scope should be checked by default.
        }

        /// <summary>
        /// Handles the GET request for the consent page. Its primary role is to validate the
        /// incoming request and prepare the view model with the list of scopes for the user to review.
        /// </summary>
        public async Task<IActionResult> OnGetAsync(
            string userId, string client_id, string? redirect_uri, string? response_type,
            [FromQuery(Name = "scope")] string? scopeFromQuery,
            string? state, string? nonce, string? code_challenge, string? code_challenge_method,
            string? returnUrl = null, CancellationToken cancellationToken = default)
        {
            // Bind all incoming OIDC parameters to the model's properties.
            UserIdFromQuery = userId; ClientId = client_id; RedirectUri = redirect_uri; ResponseType = response_type;
            OriginalScopeParameter = scopeFromQuery; State = state; Nonce = nonce; CodeChallenge = code_challenge;
            CodeChallengeMethod = code_challenge_method; ReturnUrl = returnUrl;

            _logger.LogInformation("Consent OnGet: UserId={UserId}, ClientId={ClientId}, OriginalScopeParam={OriginalScope}", UserIdFromQuery, ClientId, OriginalScopeParameter);

            if (string.IsNullOrEmpty(ClientId) || string.IsNullOrEmpty(UserIdFromQuery))
            {
                _logger.LogError("Consent OnGet: Client ID or User ID is missing from query parameters.");
                StatusMessage = "Error: Client or user context is missing for consent.";
                return Page();
            }

            var application = await _clientAppService.GetApplicationByClientIdAsync(ClientId);
            if (application == null)
            {
                _logger.LogError("Consent OnGet: Application not found for ClientId: {ClientId}", ClientId);
                StatusMessage = "Error: Invalid client application for consent.";
                return Page();
            }
            ApplicationDisplayName = await _applicationManager.GetLocalizedDisplayNameAsync(application, cancellationToken) ?? ClientId;

            // Prepare the list of scopes to display to the user.
            var requestedScopes = OriginalScopeParameter?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToImmutableArray() ?? ImmutableArray<string>.Empty;
            foreach (var scopeName in requestedScopes)
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
                        PreSelected = true
                    });
                }
                else { _logger.LogWarning("Consent OnGet: Scope {ScopeName} (requested by {ClientId}) not found.", scopeName, ClientId); }
            }

            if (!ScopesToDisplay.Any())
            {
                 _logger.LogWarning("Consent OnGet: No valid/displayable scopes for ClientId {ClientId}.", ClientId);
                 StatusMessage = "Error: No valid permissions to consent to for this application.";
            }
            return Page();
        }

        /// <summary>
        /// Handles the POST request from the consent form submission. It processes the user's decision,
        /// finalizes the claims principal, persists the authorization, and redirects back to the
        /// main Authorize endpoint to complete the flow.
        /// </summary>
        public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Consent OnPost: UserId={BoundUserId}, ClientId={BoundClientId}, Button={ButtonAction}", UserIdFromQuery, ClientId, Input.Button);

            if (string.IsNullOrEmpty(UserIdFromQuery) || string.IsNullOrEmpty(ClientId))
            {
                _logger.LogError("Consent OnPost: UserId or ClientId is missing from bound model properties.");
                StatusMessage = "Error: Critical session information is missing. Please try again.";
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null || user.Id != UserIdFromQuery)
            {
                _logger.LogWarning("Consent OnPost: Authenticated user mismatch or not found. Forcing re-authentication.");
                return Challenge(IdentityConstants.ApplicationScheme);
            }

            var application = await _clientAppService.GetApplicationByClientIdAsync(ClientId);
            if (application == null)
            {
                _logger.LogError("Consent OnPost: Application {ClientId} not found.", ClientId);
                StatusMessage = "Error: Client application not found.";
                return Page();
            }

            // Reconstruct the original OIDC request from the bound properties to pass to services.
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
            
            // Delegate consent processing to the ConsentService.
            var consentProcessingResult = await _consentService.ProcessConsentSubmissionAsync(user, application,
                Input.GrantedScopes?.ToImmutableArray() ?? ImmutableArray<string>.Empty, Input.Button == "accept", reconstructedOidcRequest);

            if (consentProcessingResult.Status == ConsentStatus.ConsentDeniedByUser || consentProcessingResult.Status == ConsentStatus.ConsentDeniedByPolicy)
            {
                _logger.LogInformation("Consent explicitly denied by user or policy for ClientId {ClientId}. Error: {Error}", ClientId, consentProcessingResult.ErrorDescription);
                // Return a ForbidResult, which OpenIddict will translate into a proper error response to the client.
                return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
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
                 await RepopulatePageModelForErrorAsync(application, cancellationToken);
                 return Page();
            }

            _logger.LogInformation("Consent accepted by user {UserId} for client {ClientId}. Granted scopes: [{GrantedScopes}]", user.Id, ClientId, string.Join(", ", consentProcessingResult.GrantedScopes));

            // With consent granted, build the final claims identity.
            var claimsIdentity = await _claimsGenerationService.BuildUserClaimsIdentityAsync(user, application,
                consentProcessingResult.GrantedScopes, reconstructedOidcRequest, cancellationToken);
            var principalToSignIn = new ClaimsPrincipal(claimsIdentity);

            // Persist the authorization grant so the user isn't prompted again.
            var authorizationEntity = await _authPersistenceService.EnsureAuthorizationAsync(principalToSignIn, user, application);
            if (authorizationEntity == null) {
                 _logger.LogError("Failed to ensure authorization persistence after consent for user {UserId}, ClientId {ClientId}", user.Id, ClientId);
                 StatusMessage = "Error: Could not save your consent. Please try again.";
                 await RepopulatePageModelForErrorAsync(application, cancellationToken);
                 return Page();
            }

            var authorizationId = await _authPersistenceService.GetAuthorizationIdAsync(authorizationEntity!);
            if (string.IsNullOrEmpty(authorizationId)) {
                _logger.LogError("Failed to retrieve ID from persisted authorization after consent for user {UserId}, ClientId {ClientId}", user.Id, ClientId);
                StatusMessage = "Error: Could not link your consent. Please try again.";
                await RepopulatePageModelForErrorAsync(application, cancellationToken);
                return Page();
            }
            claimsIdentity.SetAuthorizationId(authorizationId);

            _logger.LogInformation("Redirecting back to /Connect/Authorize to finalize OIDC flow for user {UserId}, client {ClientId}", user.Id, ClientId);
            
            // Reconstruct the original /connect/authorize URL and redirect back to it.
            // The AuthorizeModel will re-execute, but this time the consent check will pass, and it will issue the code/token.
            var authorizeRedirectParams = new Dictionary<string, string?>();
            authorizeRedirectParams[Parameters.ClientId] = ClientId;
            authorizeRedirectParams[Parameters.RedirectUri] = RedirectUri;
            authorizeRedirectParams[Parameters.ResponseType] = ResponseType;
            authorizeRedirectParams[Parameters.Scope] = OriginalScopeParameter;
            authorizeRedirectParams[Parameters.State] = State;
            authorizeRedirectParams[Parameters.Nonce] = Nonce;
            authorizeRedirectParams[Parameters.CodeChallenge] = CodeChallenge;
            authorizeRedirectParams[Parameters.CodeChallengeMethod] = CodeChallengeMethod;
            var nonNullAuthorizeRedirectParams = authorizeRedirectParams.Where(kvp => kvp.Value != null).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

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

        /// <summary>
        /// A helper method to repopulate the page's view model properties in case of an error,
        /// so the form can be redisplayed correctly.
        /// </summary>
        private async Task RepopulatePageModelForErrorAsync(AppCustomOpenIddictApplication application, CancellationToken cancellationToken)
        {
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