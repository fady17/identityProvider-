// File: Orjnz.IdentityProvider.Web/Pages/Connect/Authorize.cshtml.cs
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using Orjnz.IdentityProvider.Web.Services;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Claims;
using System.Threading; // For CancellationToken
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Orjnz.IdentityProvider.Web.Pages.Connect
{
    public class AuthorizeModel : PageModel
    {
        private const string PromptCreate = "create";

        private readonly IUserAuthenticationService _userAuthService;
        private readonly IClientApplicationService _clientAppService;
        private readonly IConsentService _consentService;
        private readonly IScopeValidationService _scopeValidationService;
        private readonly IClaimsGenerationService _claimsGenerationService;
        private readonly IAuthorizationPersistenceService _authPersistenceService;
        private readonly ILogger<AuthorizeModel> _logger;

        public AuthorizeModel(
            IUserAuthenticationService userAuthService,
            IClientApplicationService clientAppService,
            IConsentService consentService,
            IScopeValidationService scopeValidationService,
            IClaimsGenerationService claimsGenerationService,
            IAuthorizationPersistenceService authPersistenceService,
            ILogger<AuthorizeModel> logger)
        {
            _userAuthService = userAuthService;
            _clientAppService = clientAppService;
            _consentService = consentService;
            _scopeValidationService = scopeValidationService;
            _claimsGenerationService = claimsGenerationService;
            _authPersistenceService = authPersistenceService;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
            => await HandleAuthorizationRequestAsync(cancellationToken);

        public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
            => await HandleAuthorizationRequestAsync(cancellationToken);

        private async Task<IActionResult> HandleAuthorizationRequestAsync(CancellationToken cancellationToken)
        {
            var oidcRequest = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // The 'cancellationToken' parameter is HttpContext.RequestAborted.
            // We will use this for our service calls.

            // 1. User Authentication
            // HttpContext.AuthenticateAsync internally respects HttpContext.RequestAborted
            var authResult = await _userAuthService.GetAuthenticationResultAsync(HttpContext);
            string currentFullRequestUrl = Request.PathBase + Request.Path + Request.QueryString;

            if (!authResult.Succeeded)
            {
                if (oidcRequest.HasPrompt(Prompts.None))
                {
                    _logger.LogInformation("Authentication required for prompt=none request. ClientId: {ClientId}", oidcRequest.ClientId);
                    return _userAuthService.ForbidWithOidcError(Errors.LoginRequired, "The user is not logged in and prompt=none was specified.");
                }
                if (oidcRequest.HasPrompt(PromptCreate))
                {
                    _logger.LogInformation("prompt=create specified by client {ClientId}. Redirecting to registration page with ReturnUrl: {ReturnUrl}", oidcRequest.ClientId, currentFullRequestUrl);
                    return RedirectToPage("/Account/Register", new { area = "Identity", ReturnUrl = currentFullRequestUrl });
                }
                _logger.LogInformation("User not authenticated for client {ClientId}. Redirecting to login page with ReturnUrl: {ReturnUrl}", oidcRequest.ClientId, currentFullRequestUrl);
                return _userAuthService.ChallengeForLogin(HttpContext, currentFullRequestUrl);
            }

            if (!_userAuthService.IsAuthenticationSufficient(authResult, oidcRequest))
            {
                _logger.LogInformation("User authentication is not sufficient (e.g., prompt=login or max_age). Redirecting to login. ClientId: {ClientId}", oidcRequest.ClientId);
                return _userAuthService.ChallengeForLogin(HttpContext, currentFullRequestUrl);
            }

            var aspNetUser = await _userAuthService.GetAuthenticatedUserAsync(authResult.Principal);
            if (aspNetUser == null)
            {
                _logger.LogError("Authenticated user could not be retrieved from ClaimsPrincipal. Subject: {Subject}", authResult.Principal?.FindFirstValue(ClaimTypes.NameIdentifier));
                return _userAuthService.ForbidWithOidcError(Errors.ServerError, "An error occurred while retrieving user information.");
            }

            // 2. Client Application Retrieval
            // TODO: Update IClientApplicationService.GetApplicationByClientIdAsync to accept CancellationToken
            var application = await _clientAppService.GetApplicationByClientIdAsync(oidcRequest.ClientId!);
            if (application == null)
            {
                _logger.LogError("Client application not found for ClientId: {ClientId}", oidcRequest.ClientId);
                return _userAuthService.ForbidWithOidcError(Errors.InvalidClient, "The client application is not registered or is invalid.");
            }

            // 3. Consent Check
            // TODO: Update IConsentService.CheckConsentAsync to accept CancellationToken
            var consentResult = await _consentService.CheckConsentAsync(aspNetUser, application, oidcRequest.GetScopes(), oidcRequest);
            ImmutableArray<string> consentedScopesFromService;

            switch (consentResult.Status)
            {
                case ConsentStatus.ConsentRequired:
                    _logger.LogInformation("Consent required for user {UserId}, client {ClientId}. Redirecting to consent page.", aspNetUser.Id, oidcRequest.ClientId);
                    var routeValues = new Dictionary<string, string?>
                    {
                        { "userId", aspNetUser.Id }, { "client_id", oidcRequest.ClientId },
                        { "redirect_uri", oidcRequest.RedirectUri }, { "response_type", oidcRequest.ResponseType },
                        { "scope", oidcRequest.Scope }, { "state", oidcRequest.State },
                        { "nonce", oidcRequest.Nonce }, { "code_challenge", oidcRequest.CodeChallenge },
                        { "code_challenge_method", oidcRequest.CodeChallengeMethod }
                    };
                    var nonNullRouteValues = routeValues.Where(kvp => kvp.Value != null).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
                    return RedirectToPage("/Connect/Consent", nonNullRouteValues);

                case ConsentStatus.ConsentDeniedByPolicy: case ConsentStatus.ConsentDeniedByUser:
                    _logger.LogWarning("Consent denied for user {UserId}, client {ClientId}. Status: {ConsentStatus}, Error: {Error}, Desc: {ErrorDesc}",
                        aspNetUser.Id, oidcRequest.ClientId, consentResult.Status, consentResult.Error, consentResult.ErrorDescription);
                    return _userAuthService.ForbidWithOidcError(consentResult.Error ?? Errors.AccessDenied, consentResult.ErrorDescription ?? "Consent was denied.");
                
                case ConsentStatus.Error:
                     _logger.LogError("Error during consent check for user {UserId}, client {ClientId}. Error: {Error}, Desc: {ErrorDesc}",
                        aspNetUser.Id, oidcRequest.ClientId, consentResult.Error, consentResult.ErrorDescription);
                    return _userAuthService.ForbidWithOidcError(consentResult.Error ?? Errors.ServerError, consentResult.ErrorDescription ?? "An error occurred during the consent process.");

                case ConsentStatus.ConsentGranted: case ConsentStatus.ConsentImplicitlyGranted:
                    _logger.LogInformation("Consent granted (status: {ConsentStatus}) for user {UserId}, client {ClientId}.", consentResult.Status, aspNetUser.Id, oidcRequest.ClientId);
                    consentedScopesFromService = consentResult.GrantedScopes;
                    break;
                default:
                     _logger.LogError("Unknown consent status: {ConsentStatus}", consentResult.Status);
                    return _userAuthService.ForbidWithOidcError(Errors.ServerError, "An unexpected error occurred during consent processing.");
            }

            // 4. Scope Validation
            // TODO: Update IClientApplicationService.GetClientPermissionsAsync and IScopeValidationService.ValidateAndFilterScopesAsync to accept CancellationToken
            var clientPermissions = await _clientAppService.GetClientPermissionsAsync(application);
            var finalValidatedScopes = await _scopeValidationService.ValidateAndFilterScopesAsync(
                consentedScopesFromService, application, clientPermissions);

            if (!finalValidatedScopes.Any())
            {
                _logger.LogWarning("No valid scopes remained after validation for client {ClientId}, user {UserId}.", oidcRequest.ClientId, aspNetUser.Id);
                return _userAuthService.ForbidWithOidcError(Errors.InvalidScope, "No valid scopes were granted or permitted.");
            }

            // 5. Claims & Principal Construction
            var claimsIdentity = await _claimsGenerationService.BuildUserClaimsIdentityAsync(
                aspNetUser,
                application, // This is AppCustomOpenIddictApplication
                finalValidatedScopes,
                oidcRequest,
                cancellationToken // Pass the CancellationToken from HttpContext.RequestAborted
            );
            var principalToSignIn = new ClaimsPrincipal(claimsIdentity);

            // 6. Persist Authorization
            // TODO: Update IAuthorizationPersistenceService.EnsureAuthorizationAsync to accept CancellationToken
            var authorizationEntity = await _authPersistenceService.EnsureAuthorizationAsync(
                principalToSignIn,
                aspNetUser,
                application
            );

            if (authorizationEntity == null)
            {
                 _logger.LogError("Failed to ensure authorization persistence for user {UserId}, client {ClientId}", aspNetUser.Id, oidcRequest.ClientId);
                return _userAuthService.ForbidWithOidcError(Errors.ServerError, "Could not save authorization grant.");
            }

            // TODO: Update IAuthorizationPersistenceService.GetAuthorizationIdAsync to accept CancellationToken
            var authorizationId = await _authPersistenceService.GetAuthorizationIdAsync(authorizationEntity);
            if (string.IsNullOrEmpty(authorizationId))
            {
                _logger.LogError("Failed to retrieve ID from persisted authorization for user {UserId}, client {ClientId}", aspNetUser.Id, oidcRequest.ClientId);
                return _userAuthService.ForbidWithOidcError(Errors.ServerError, "Could not link authorization grant.");
            }
            claimsIdentity.SetAuthorizationId(authorizationId);

            // 7. Return SignInResult to OpenIddict
            _logger.LogInformation("Successfully processed authorization request for user {UserId}, client {ClientId}. Issuing SignInResult.", aspNetUser.Id, oidcRequest.ClientId);
            return SignIn(principalToSignIn, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
    }
}