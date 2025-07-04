using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
// using OpenIddict.EntityFrameworkCore.Models; // No longer needed if AppCustom is used
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading; // For CancellationToken
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Implements the scope validation logic by cross-referencing requested scopes with system-defined
    /// scopes and the specific permissions granted to a client application.
    /// </summary>
    public class ScopeValidationService : IScopeValidationService
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ILogger<ScopeValidationService> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="ScopeValidationService"/> class.
        /// </summary>
        /// <param name="scopeManager">The OpenIddict manager for scope entities.</param>
        /// <param name="applicationManager">The OpenIddict manager for application entities.</param>
        /// <param name="logger">The logger for recording service operations.</param>
        public ScopeValidationService(
            IOpenIddictScopeManager scopeManager,
            IOpenIddictApplicationManager applicationManager,
            ILogger<ScopeValidationService> logger)
        {
            _scopeManager = scopeManager ?? throw new ArgumentNullException(nameof(scopeManager));
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public async Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
            ImmutableArray<string> requestedScopes,
            AppCustomOpenIddictApplication application,
            ImmutableArray<string> clientPermissions,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(application);
            if (requestedScopes.IsDefaultOrEmpty)
            {
                _logger.LogDebug("No scopes requested, returning empty array.");
                return ImmutableArray<string>.Empty;
            }

            var finalGrantedScopes = new HashSet<string>();
            var allSystemScopeNames = new HashSet<string>();

            // 1. Fetch all scopes defined in the Identity Provider system. This creates a master list of valid scopes.
            await foreach (var scopeEntryObject in _scopeManager.ListAsync(cancellationToken: cancellationToken).WithCancellation(cancellationToken))
            {
                var name = await _scopeManager.GetNameAsync(scopeEntryObject, cancellationToken);
                if (!string.IsNullOrEmpty(name))
                {
                    allSystemScopeNames.Add(name);
                }
            }
            
            var clientIdForLogging = application.ClientId ?? await _applicationManager.GetClientIdAsync(application, cancellationToken);

            _logger.LogDebug("System defined scopes: [{SystemScopes}]", string.Join(", ", allSystemScopeNames));
            _logger.LogDebug("Client {ClientId} requested scopes: [{RequestedScopes}]", clientIdForLogging, string.Join(", ", requestedScopes));
            _logger.LogDebug("Client {ClientId} has permissions: [{ClientPermissions}]", clientIdForLogging, string.Join(", ", clientPermissions));

            // 2. Iterate through each requested scope and apply validation rules.
            foreach (var requestedScope in requestedScopes)
            {
                if (string.IsNullOrEmpty(requestedScope)) continue;

                // Rule for standard OIDC scopes (profile, email, etc.): They only need to be registered in the system.
                // Their usage is governed by the grant types allowed for the client, not typically a `scp:` permission.
                if (requestedScope == Scopes.OpenId ||
                    requestedScope == Scopes.Profile ||
                    requestedScope == Scopes.Email ||
                    requestedScope == Scopes.Phone ||
                    requestedScope == Scopes.Address ||
                    requestedScope == Scopes.Roles ||
                    requestedScope == Scopes.OfflineAccess)
                {
                    if (allSystemScopeNames.Contains(requestedScope))
                    {
                        finalGrantedScopes.Add(requestedScope);
                        _logger.LogDebug("Standard scope '{Scope}' is valid and added for client {ClientId}.", requestedScope, clientIdForLogging);
                    }
                    else
                    {
                        // This indicates a misconfiguration; a standard scope that is expected to exist is not registered.
                        _logger.LogWarning("Standard OIDC scope '{Scope}' requested by client {ClientId} but not registered in the system.", requestedScope, clientIdForLogging);
                    }
                    continue;
                }

                // Rule for custom API scopes: The scope must exist in the system AND the client must have
                // an explicit permission for it (e.g., a permission string like "scp:my-api-scope").
                if (allSystemScopeNames.Contains(requestedScope) &&
                    clientPermissions.Contains(Permissions.Prefixes.Scope + requestedScope))
                {
                    finalGrantedScopes.Add(requestedScope);
                     _logger.LogDebug("Custom scope '{Scope}' is valid and permitted for client {ClientId}.", requestedScope, clientIdForLogging);
                }
                else
                {
                    // Log the specific reason for failure for easier debugging.
                    if (!allSystemScopeNames.Contains(requestedScope))
                    {
                        _logger.LogWarning("Scope '{Scope}' requested by client {ClientId} is not a registered system scope.", requestedScope, clientIdForLogging);
                    }
                    else if (!clientPermissions.Contains(Permissions.Prefixes.Scope + requestedScope))
                    {
                        _logger.LogWarning("Scope '{Scope}' requested by client {ClientId} is a system scope but client lacks permission '{PermissionPrefix}{Scope}'.",
                            requestedScope, clientIdForLogging, Permissions.Prefixes.Scope, requestedScope);
                    }
                }
            }
            
            _logger.LogInformation("For client {ClientId}, originally requested scopes [{RequestedScopes}], validated and filtered to [{FinalScopes}]",
                clientIdForLogging, string.Join(", ", requestedScopes), string.Join(", ", finalGrantedScopes));
            
            // 3. Return the filtered, validated set of scopes.
            return finalGrantedScopes.ToImmutableArray();
        }

        /// <inheritdoc/>
        public async Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
            ImmutableArray<string> requestedScopes,
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(application);
            // This overload fetches the client's permissions before delegating to the main validation method.
            var clientPermissions = await _applicationManager.GetPermissionsAsync(application, cancellationToken);
            return await ValidateAndFilterScopesAsync(requestedScopes, application, clientPermissions, cancellationToken);
        }
    }
}