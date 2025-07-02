// File: Orjnz.IdentityProvider.Web/Services/ScopeValidationService.cs
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
    public class ScopeValidationService : IScopeValidationService
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ILogger<ScopeValidationService> _logger;

        public ScopeValidationService(
            IOpenIddictScopeManager scopeManager,
            IOpenIddictApplicationManager applicationManager,
            ILogger<ScopeValidationService> logger)
        {
            _scopeManager = scopeManager ?? throw new ArgumentNullException(nameof(scopeManager));
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
            ImmutableArray<string> requestedScopes,
            AppCustomOpenIddictApplication application, // Changed parameter type
            ImmutableArray<string> clientPermissions,
            CancellationToken cancellationToken = default) // Added CancellationToken
        {
            ArgumentNullException.ThrowIfNull(application); // clientPermissions can be empty, not null checked here explicitly
            if (requestedScopes.IsDefaultOrEmpty)
            {
                _logger.LogDebug("No scopes requested, returning empty array.");
                return ImmutableArray<string>.Empty;
            }

            var finalGrantedScopes = new HashSet<string>();
            var allSystemScopeNames = new HashSet<string>();

            // Pass CancellationToken to ListAsync and use WithCancellation for await foreach
            await foreach (var scopeEntryObject in _scopeManager.ListAsync(cancellationToken: cancellationToken).WithCancellation(cancellationToken))
            {
                var name = await _scopeManager.GetNameAsync(scopeEntryObject, cancellationToken);
                if (!string.IsNullOrEmpty(name))
                {
                    allSystemScopeNames.Add(name);
                }
            }
            
            // GetClientIdAsync can take the custom app type and CancellationToken
            var clientIdForLogging = application.ClientId ?? await _applicationManager.GetClientIdAsync(application, cancellationToken);

            _logger.LogDebug("System defined scopes: [{SystemScopes}]", string.Join(", ", allSystemScopeNames));
            _logger.LogDebug("Client {ClientId} requested scopes: [{RequestedScopes}]", clientIdForLogging, string.Join(", ", requestedScopes));
            _logger.LogDebug("Client {ClientId} has permissions: [{ClientPermissions}]", clientIdForLogging, string.Join(", ", clientPermissions));

            foreach (var requestedScope in requestedScopes)
            {
                if (string.IsNullOrEmpty(requestedScope)) continue;

                // Standard OIDC scopes are generally allowed if registered in the system,
                // client permissions for them are often implicit or managed by specific grant type permissions.
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
                        _logger.LogWarning("Standard OIDC scope '{Scope}' requested by client {ClientId} but not registered in the system.", requestedScope, clientIdForLogging);
                    }
                    continue;
                }

                // For custom API scopes, check if they exist and if the client has the scp: prefix permission
                if (allSystemScopeNames.Contains(requestedScope) &&
                    clientPermissions.Contains(Permissions.Prefixes.Scope + requestedScope))
                {
                    finalGrantedScopes.Add(requestedScope);
                     _logger.LogDebug("Custom scope '{Scope}' is valid and permitted for client {ClientId}.", requestedScope, clientIdForLogging);
                }
                else
                {
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

            return finalGrantedScopes.ToImmutableArray();
        }

        public async Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
            ImmutableArray<string> requestedScopes,
            AppCustomOpenIddictApplication application, // Changed parameter type
            CancellationToken cancellationToken = default) // Added CancellationToken
        {
            ArgumentNullException.ThrowIfNull(application);
            // Pass CancellationToken to GetPermissionsAsync
            var clientPermissions = await _applicationManager.GetPermissionsAsync(application, cancellationToken);
            return await ValidateAndFilterScopesAsync(requestedScopes, application, clientPermissions, cancellationToken);
        }
    }
}
// // File: Orjnz.IdentityProvider.Web/Services/ScopeValidationService.cs
// using Microsoft.Extensions.Logging;
// using OpenIddict.Abstractions;
// using OpenIddict.EntityFrameworkCore.Models; // For casting if needed, though manager methods should work with object
// using System;
// using System.Collections.Generic;
// using System.Collections.Immutable;
// using System.Linq;
// using System.Threading.Tasks;
// using static OpenIddict.Abstractions.OpenIddictConstants;

// namespace Orjnz.IdentityProvider.Web.Services
// {
//     public class ScopeValidationService : IScopeValidationService
//     {
//         private readonly IOpenIddictScopeManager _scopeManager;
//         private readonly IOpenIddictApplicationManager _applicationManager;
//         private readonly ILogger<ScopeValidationService> _logger;

//         public ScopeValidationService(
//             IOpenIddictScopeManager scopeManager,
//             IOpenIddictApplicationManager applicationManager,
//             ILogger<ScopeValidationService> logger)
//         {
//             _scopeManager = scopeManager ?? throw new ArgumentNullException(nameof(scopeManager));
//             _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
//             _logger = logger ?? throw new ArgumentNullException(nameof(logger));
//         }

//         public async Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
//             ImmutableArray<string> requestedScopes,
//             OpenIddictEntityFrameworkCoreApplication application, // Assuming concrete type for application
//             ImmutableArray<string> clientPermissions)
//         {
//             ArgumentNullException.ThrowIfNull(application);
//             if (requestedScopes.IsDefaultOrEmpty)
//             {
//                 _logger.LogDebug("No scopes requested, returning empty array.");
//                 return ImmutableArray<string>.Empty;
//             }

//             var finalGrantedScopes = new HashSet<string>();

//             // --- CORRECTED: Get all system scope names ---
//             var allSystemScopeNames = new HashSet<string>();
//             await foreach (var scopeEntryObject in _scopeManager.ListAsync())
//             {
//                 // GetNameAsync takes the 'object' returned by ListAsync()
//                 var name = await _scopeManager.GetNameAsync(scopeEntryObject);
//                 if (!string.IsNullOrEmpty(name))
//                 {
//                     allSystemScopeNames.Add(name);
//                 }
//             }
//             // --- END CORRECTION ---
            
//             _logger.LogDebug("System defined scopes: [{SystemScopes}]", string.Join(", ", allSystemScopeNames));
//             _logger.LogDebug("Client {ClientId} requested scopes: [{RequestedScopes}]", await _applicationManager.GetClientIdAsync(application), string.Join(", ", requestedScopes));
//             _logger.LogDebug("Client {ClientId} has permissions: [{ClientPermissions}]", await _applicationManager.GetClientIdAsync(application), string.Join(", ", clientPermissions));

//             foreach (var requestedScope in requestedScopes)
//             {
//                 if (string.IsNullOrEmpty(requestedScope)) continue;

//                 if (requestedScope == Scopes.OpenId ||
//                     requestedScope == Scopes.Profile ||
//                     requestedScope == Scopes.Email ||
//                     requestedScope == Scopes.Phone ||
//                     requestedScope == Scopes.Address ||
//                     requestedScope == Scopes.Roles ||
//                     requestedScope == Scopes.OfflineAccess)
//                 {
//                     if (allSystemScopeNames.Contains(requestedScope))
//                     {
//                         finalGrantedScopes.Add(requestedScope);
//                         _logger.LogDebug("Standard scope {Scope} is valid and added for client {ClientId}.", requestedScope, await _applicationManager.GetClientIdAsync(application));
//                     }
//                     else
//                     {
//                         _logger.LogWarning("Standard scope {Scope} requested by client {ClientId} but not registered in the system.", requestedScope, await _applicationManager.GetClientIdAsync(application));
//                     }
//                     continue;
//                 }

//                 if (allSystemScopeNames.Contains(requestedScope) &&
//                     clientPermissions.Contains(Permissions.Prefixes.Scope + requestedScope))
//                 {
//                     finalGrantedScopes.Add(requestedScope);
//                      _logger.LogDebug("Custom scope {Scope} is valid and permitted for client {ClientId}.", requestedScope, await _applicationManager.GetClientIdAsync(application));
//                 }
//                 else
//                 {
//                     if (!allSystemScopeNames.Contains(requestedScope))
//                     {
//                         _logger.LogWarning("Scope {Scope} requested by client {ClientId} is not a registered system scope.", requestedScope, await _applicationManager.GetClientIdAsync(application));
//                     }
//                     else if (!clientPermissions.Contains(Permissions.Prefixes.Scope + requestedScope))
//                     {
//                         _logger.LogWarning("Scope {Scope} requested by client {ClientId} is a system scope but client lacks permission '{PermissionPrefix}{Scope}'.",
//                             requestedScope, await _applicationManager.GetClientIdAsync(application), Permissions.Prefixes.Scope, requestedScope);
//                     }
//                 }
//             }
            
//             _logger.LogInformation("For client {ClientId}, originally requested scopes [{RequestedScopes}], validated and filtered to [{FinalScopes}]",
//                 await _applicationManager.GetClientIdAsync(application), string.Join(", ", requestedScopes), string.Join(", ", finalGrantedScopes));

//             return finalGrantedScopes.ToImmutableArray();
//         }

//         public async Task<ImmutableArray<string>> ValidateAndFilterScopesAsync(
//             ImmutableArray<string> requestedScopes,
//             OpenIddictEntityFrameworkCoreApplication application)
//         {
//             ArgumentNullException.ThrowIfNull(application);
//             var clientPermissions = await _applicationManager.GetPermissionsAsync(application);
//             return await ValidateAndFilterScopesAsync(requestedScopes, application, clientPermissions);
//         }
//     }
// }
