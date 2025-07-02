// File: Orjnz.IdentityProvider.Web/Services/ClientApplicationService.cs
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
    public class ClientApplicationService : IClientApplicationService
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ILogger<ClientApplicationService> _logger;

        public ClientApplicationService(
            IOpenIddictApplicationManager applicationManager,
            ILogger<ClientApplicationService> logger)
        {
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<AppCustomOpenIddictApplication?> GetApplicationByClientIdAsync(
            string clientId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                return null;
            }
            // Pass CancellationToken to the manager method
            var applicationObject = await _applicationManager.FindByClientIdAsync(clientId, cancellationToken);
            if (applicationObject == null)
            {
                _logger.LogWarning("No application found for ClientId: {ClientId}", clientId);
                return null;
            }
            if (applicationObject is AppCustomOpenIddictApplication customApplication)
            {
                return customApplication;
            }

            // This indicates a potential misconfiguration if ReplaceDefaultEntities isn't working as expected.
            _logger.LogError("Application found for ClientId {ClientId} but was of unexpected type {ActualType}. Expected {ExpectedType}.",
                clientId, applicationObject.GetType().FullName, typeof(AppCustomOpenIddictApplication).FullName);
            // Consider throwing an exception here if this state is critical
            // throw new InvalidCastException($"Application for ClientId {clientId} is not of type {nameof(AppCustomOpenIddictApplication)}.");
            return null;
        }

        public async Task<string?> GetApplicationIdAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(application);
            // Pass CancellationToken to the manager method
            return await _applicationManager.GetIdAsync(application, cancellationToken);
        }

        public async Task<string?> GetApplicationConsentTypeAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(application);
            // Pass CancellationToken to the manager method
            return await _applicationManager.GetConsentTypeAsync(application, cancellationToken);
        }

        public async Task<ImmutableArray<string>> GetClientPermissionsAsync(
            AppCustomOpenIddictApplication application,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(application);
            // Pass CancellationToken to the manager method
            return await _applicationManager.GetPermissionsAsync(application, cancellationToken);
        }

        // This is a synchronous method, directly accessing a property. No CancellationToken needed.
        public Guid? GetProviderIdFromApplication(AppCustomOpenIddictApplication application)
        {
             ArgumentNullException.ThrowIfNull(application);
             return application.ProviderId;
        }
    }
}