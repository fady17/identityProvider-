// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Applications/Details.cshtml.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions; // For IOpenIddictApplicationManager and constants
using Orjnz.IdentityProvider.Web.Data; // For ApplicationDbContext (to get Provider name)
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System;
using System.Collections.Generic;
using System.Collections.Immutable; // For ImmutableArray
using System.Linq;
using System.Text.Json; // For JsonElement display
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Applications
{
    // Authorization handled by convention
    public class DetailsModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ApplicationDbContext _dbContext; // To fetch Provider display name
        private readonly ILogger<DetailsModel> _logger;

        public DetailsModel(
            IOpenIddictApplicationManager applicationManager,
            ApplicationDbContext dbContext,
            ILogger<DetailsModel> logger)
        {
            _applicationManager = applicationManager;
            _dbContext = dbContext;
            _logger = logger;
        }

        public ApplicationDetailsViewModel? Application { get; set; }

        // ViewModel for displaying detailed application information
        public class ApplicationDetailsViewModel
        {
            public string? Id { get; set; }
            public string? ClientId { get; set; }
            public string? DisplayName { get; set; }
            public string? ClientSecret { get; set; } // Will just indicate if set, not show value
            public string? ClientType { get; set; }
            public string? ApplicationType { get; set; }
            public string? ConsentType { get; set; }
            public ImmutableArray<string> RedirectUris { get; set; } = ImmutableArray<string>.Empty;
            public ImmutableArray<string> PostLogoutRedirectUris { get; set; } = ImmutableArray<string>.Empty;
            public ImmutableArray<string> Permissions { get; set; } = ImmutableArray<string>.Empty;
            public ImmutableArray<string> Requirements { get; set; } = ImmutableArray<string>.Empty;
            public Guid? ProviderId { get; set; }
            public string? ProviderName { get; set; }
            public string? SettingsJson { get; set; } // Display raw JSON for settings
            public string? PropertiesJson { get; set; } // Display raw JSON for properties
        }

        public async Task<IActionResult> OnGetAsync(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Application Details GET: ID is null or empty.");
                return NotFound("Application ID not specified.");
            }

            var appObject = await _applicationManager.FindByIdAsync(id);
            if (appObject == null || !(appObject is AppCustomOpenIddictApplication customApplication))
            {
                _logger.LogWarning("Application Details GET: Application with ID {ApplicationId} not found or not of expected type.", id);
                return NotFound($"Application with ID '{id}' not found or is not of the correct type.");
            }

            string? providerName = null;
            if (customApplication.ProviderId.HasValue)
            {
                var provider = await _dbContext.Providers.FindAsync(customApplication.ProviderId.Value);
                providerName = provider?.Name;
            }

            // Fetching properties and settings
            var appProperties = await _applicationManager.GetPropertiesAsync(customApplication);
            var appSettings = await _applicationManager.GetSettingsAsync(customApplication);

            // Check if client has a secret by examining the client type and descriptor
            var clientType = await _applicationManager.GetClientTypeAsync(customApplication);
            var hasClientSecret = clientType == OpenIddictConstants.ClientTypes.Confidential;
            
            string clientSecretDisplay;
            if (hasClientSecret)
            {
                clientSecretDisplay = "(Secret Set - Confidential Client)";
            }
            else
            {
                clientSecretDisplay = "(No Secret - Public Client)";
            }

            Application = new ApplicationDetailsViewModel
            {
                Id = await _applicationManager.GetIdAsync(customApplication),
                ClientId = await _applicationManager.GetClientIdAsync(customApplication),
                DisplayName = await _applicationManager.GetDisplayNameAsync(customApplication),
                ClientSecret = clientSecretDisplay,
                ClientType = clientType,
                ApplicationType = await _applicationManager.GetApplicationTypeAsync(customApplication),
                ConsentType = await _applicationManager.GetConsentTypeAsync(customApplication),
                RedirectUris = await _applicationManager.GetRedirectUrisAsync(customApplication),
                PostLogoutRedirectUris = await _applicationManager.GetPostLogoutRedirectUrisAsync(customApplication),
                Permissions = await _applicationManager.GetPermissionsAsync(customApplication),
                Requirements = await _applicationManager.GetRequirementsAsync(customApplication),
                ProviderId = customApplication.ProviderId,
                ProviderName = providerName,
                SettingsJson = appSettings.Any() ? JsonSerializer.Serialize(appSettings, new JsonSerializerOptions { WriteIndented = true }) : "No settings configured.",
                PropertiesJson = appProperties.Any() ? JsonSerializer.Serialize(appProperties, new JsonSerializerOptions { WriteIndented = true }) : "No custom properties configured."
            };

            return Page();
        }
    }
}