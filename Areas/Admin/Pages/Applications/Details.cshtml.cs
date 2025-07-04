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
    /// <summary>
    /// This Razor Page model handles displaying the detailed information of a single client application.
    /// It provides a read-only view of all configured properties.
    /// </summary>
    /// <remarks>
    /// Authorization is handled by convention in `Program.cs`.
    /// </remarks>
    public class DetailsModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ApplicationDbContext _dbContext; // To fetch Provider display name
        private readonly ILogger<DetailsModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="DetailsModel"/> class.
        /// </summary>
        public DetailsModel(
            IOpenIddictApplicationManager applicationManager,
            ApplicationDbContext dbContext,
            ILogger<DetailsModel> logger)
        {
            _applicationManager = applicationManager;
            _dbContext = dbContext;
            _logger = logger;
        }

        /// <summary>
        /// The view model holding the detailed application data to be displayed on the page.
        /// </summary>
        public ApplicationDetailsViewModel? Application { get; set; }

        /// <summary>
        /// A view model specifically for displaying all details of an application.
        /// </summary>
        public class ApplicationDetailsViewModel
        {
            public string? Id { get; set; }
            public string? ClientId { get; set; }
            public string? DisplayName { get; set; }
            public string? ClientSecret { get; set; } // Will just indicate if set, not show the actual value.
            public string? ClientType { get; set; }
            public string? ApplicationType { get; set; }
            public string? ConsentType { get; set; }
            public ImmutableArray<string> RedirectUris { get; set; } = ImmutableArray<string>.Empty;
            public ImmutableArray<string> PostLogoutRedirectUris { get; set; } = ImmutableArray<string>.Empty;
            public ImmutableArray<string> Permissions { get; set; } = ImmutableArray<string>.Empty;
            public ImmutableArray<string> Requirements { get; set; } = ImmutableArray<string>.Empty;
            public Guid? ProviderId { get; set; }
            public string? ProviderName { get; set; }
            public string? SettingsJson { get; set; } // For displaying raw JSON settings.
            public string? PropertiesJson { get; set; } // For displaying raw JSON custom properties.
        }

        /// <summary>
        /// Handles the GET request for the details page. It fetches all properties of the
        /// specified application and populates the view model.
        /// </summary>
        /// <param name="id">The unique identifier of the application to display.</param>
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

            // Fetch the associated provider's name if a link exists.
            string? providerName = null;
            if (customApplication.ProviderId.HasValue)
            {
                var provider = await _dbContext.Providers.FindAsync(customApplication.ProviderId.Value);
                providerName = provider?.Name;
            }
            
            // Fetch advanced properties like custom settings and properties.
            var appProperties = await _applicationManager.GetPropertiesAsync(customApplication);
            var appSettings = await _applicationManager.GetSettingsAsync(customApplication);

            // Determine if a client secret is set without exposing the secret itself.
            var clientType = await _applicationManager.GetClientTypeAsync(customApplication);
            var hasClientSecret = clientType == OpenIddictConstants.ClientTypes.Confidential;
            string clientSecretDisplay = hasClientSecret ? "(Secret Set - Confidential Client)" : "(No Secret - Public Client)";

            // Populate the detailed view model with all retrieved information.
            Application = new ApplicationDetailsViewModel
            {
                Id = await _applicationManager.GetIdAsync(customApplication),
                ClientId = await _applicationManager.GetClientIdAsync(customApplication),
                DisplayName = await _applicationManager.GetDisplayNameAsync(customApplication),
                ClientSecret = clientSecretDisplay,
                ClientType = clientType,
                ApplicationType = await _applicationManager.GetApplicationTypeAsync(customApplication),
                ConsentType = await _applicationManager.GetConsentTypeAsync(customApplication),
                RedirectUris = (await _applicationManager.GetRedirectUrisAsync(customApplication)).ToImmutableArray(),
                PostLogoutRedirectUris = (await _applicationManager.GetPostLogoutRedirectUrisAsync(customApplication)).ToImmutableArray(),
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