using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System;
using System.Collections.Immutable;
// using System.Text.Json; // No longer needed
using System.Threading; // For CancellationToken
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Implements the service for retrieving and managing client application data.
    /// This class wraps the `IOpenIddictApplicationManager` to provide a strongly-typed,
    /// application-specific interface for handling client entities.
    /// </summary>
    public class ClientApplicationService : IClientApplicationService
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ILogger<ClientApplicationService> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="ClientApplicationService"/> class.
        /// </summary>
        /// <param name="applicationManager">The OpenIddict manager for application entities.</param>
        /// <param name="logger">The logger for recording service operations.</param>
        public ClientApplicationService(
            IOpenIddictApplicationManager applicationManager,
            ILogger<ClientApplicationService> logger)
        {
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public async Task<AppCustomOpenIddictApplication?> GetApplicationByClientIdAsync(
            string clientId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                return null;
            }
            
            // Delegate the call to the underlying OpenIddict manager to find the application.
            var applicationObject = await _applicationManager.FindByClientIdAsync(clientId, cancellationToken);
            if (applicationObject == null)
            {
                _logger.LogWarning("No application found for ClientId: {ClientId}", clientId);
                return null;
            }

            // The manager returns a base object type. We must cast it to our custom, derived type.
            // This ensures that downstream code can access custom properties like `ProviderId`.
            if (applicationObject is AppCustomOpenIddictApplication customApplication)
            {
                return customApplication;
            }

            // This is a critical error condition. If this occurs, it likely means that the OpenIddict
            // configuration (`ReplaceDefaultEntities`) is not set up correctly in Program.cs.
            _logger.LogError("Application found for ClientId {ClientId} but was of unexpected type {ActualType}. Expected {ExpectedType}.",
                clientId, applicationObject.GetType().FullName, typeof(AppCustomOpenIddictApplication).FullName);
            
            // For robustness, return null to prevent an invalid cast from propagating.
            // In a strict environment, throwing an exception might be preferred.
            return null;
        }

        /// <inheritdoc/>
        public async Task<string?> GetApplicationIdAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(application);
            // This is a pass-through method that delegates to the application manager.
            return await _applicationManager.GetIdAsync(application, cancellationToken);
        }

        /// <inheritdoc/>
        public async Task<string?> GetApplicationConsentTypeAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(application);
            // This is a pass-through method that delegates to the application manager.
            return await _applicationManager.GetConsentTypeAsync(application, cancellationToken);
        }

        /// <inheritdoc/>
        public async Task<ImmutableArray<string>> GetClientPermissionsAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(application);
            // This is a pass-through method that delegates to the application manager.
            return await _applicationManager.GetPermissionsAsync(application, cancellationToken);
        }

        /// <inheritdoc/>
        public Guid? GetProviderIdFromApplication(AppCustomOpenIddictApplication application)
        {
             ArgumentNullException.ThrowIfNull(application);
             // Directly access the custom `ProviderId` property from our derived entity class.
             // This is a primary benefit of using custom OpenIddict entities.
             return application.ProviderId;
        }
    }
}