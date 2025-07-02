// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Applications/Create.cshtml.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering; // For SelectList, SelectListItem
using Microsoft.EntityFrameworkCore; // For ToListAsync
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions; // For IOpenIddictApplicationManager, OpenIddictApplicationDescriptor, Constants
using Orjnz.IdentityProvider.Web.Areas.Admin.Models; // For ApplicationViewModel
using Orjnz.IdentityProvider.Web.Data; // For ApplicationDbContext, Provider
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants; // For easy access to constants

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Applications
{
    // Authorization handled by convention in Program.cs
    public class CreateModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager; // To list available scopes for permissions
        private readonly ApplicationDbContext _dbContext; // To list providers
        private readonly ILogger<CreateModel> _logger;

        public CreateModel(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            ApplicationDbContext dbContext,
            ILogger<CreateModel> logger)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
            _dbContext = dbContext;
            _logger = logger;
        }

        [BindProperty]
        public ApplicationViewModel ApplicationInput { get; set; } = new ApplicationViewModel();

        // For pre-populating based on query string, e.g., when coming from "Add Application for this Provider"
        [BindProperty(SupportsGet = true)]
        public Guid? PreSelectedProviderId { get; set; }


        public async Task<IActionResult> OnGetAsync()
        {
            await PopulateSelectListsAsync();

            // Pre-select provider if ID is passed in query string
            if (PreSelectedProviderId.HasValue)
            {
                ApplicationInput.ProviderId = PreSelectedProviderId.Value;
            }
            ApplicationInput.ClientType = ClientTypes.Public; // Default to Public
            
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Trim string inputs
            ApplicationInput.ClientId = ApplicationInput.ClientId?.Trim() ?? string.Empty;
            ApplicationInput.DisplayName = ApplicationInput.DisplayName?.Trim() ?? string.Empty;
            ApplicationInput.ClientSecret = ApplicationInput.ClientSecret?.Trim(); // Null if empty

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Create Application POST: Model state is invalid.");
                await PopulateSelectListsAsync(); // Repopulate dropdowns before returning page
                return Page();
            }

            // Check for ClientId uniqueness
            if (await _applicationManager.FindByClientIdAsync(ApplicationInput.ClientId) != null)
            {
                _logger.LogWarning("Create Application POST: ClientId '{ClientId}' already exists.", ApplicationInput.ClientId);
                ModelState.AddModelError(nameof(ApplicationViewModel.ClientId), "This Client ID is already in use. Please choose another.");
                await PopulateSelectListsAsync();
                return Page();
            }

            // Validate ClientSecret for confidential clients
            if (ApplicationInput.ClientType == ClientTypes.Confidential && string.IsNullOrWhiteSpace(ApplicationInput.ClientSecret))
            {
                ModelState.AddModelError(nameof(ApplicationViewModel.ClientSecret), "Client secret is required for confidential clients.");
                await PopulateSelectListsAsync();
                return Page();
            }
            if (ApplicationInput.ClientType == ClientTypes.Public && !string.IsNullOrEmpty(ApplicationInput.ClientSecret))
            {
                _logger.LogInformation("Client secret provided for a public client '{ClientId}'. It will be ignored/nulled.", ApplicationInput.ClientId);
                ApplicationInput.ClientSecret = null; // Public clients must not have a secret
            }


            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = ApplicationInput.ClientId,
                ClientSecret = ApplicationInput.ClientSecret, // OpenIddict will hash this if it's a confidential client
                DisplayName = ApplicationInput.DisplayName,
                ClientType = ApplicationInput.ClientType,
                ApplicationType = ApplicationInput.ApplicationType,
                ConsentType = ApplicationInput.ConsentType
            };

            // Add URIs
            foreach (var uri in ApplicationInput.GetRedirectUrisAsImmutableArray()) { descriptor.RedirectUris.Add(uri); }
            foreach (var uri in ApplicationInput.GetPostLogoutRedirectUrisAsImmutableArray()) { descriptor.PostLogoutRedirectUris.Add(uri); }

            // Add Permissions & Requirements
            descriptor.Permissions.UnionWith(ApplicationInput.SelectedPermissions);
            descriptor.Requirements.UnionWith(ApplicationInput.SelectedRequirements);
            
            // If custom settings/properties were part of ApplicationViewModel and a form, they'd be added here.
            // descriptor.Settings["my_setting"] = "value";
            // descriptor.Properties["custom_prop"] = System.Text.Json.JsonSerializer.SerializeToElement("custom_value");


            try
            {
                var applicationObject = await _applicationManager.CreateAsync(descriptor);
                if (applicationObject == null)
                {
                    throw new InvalidOperationException("Application creation returned null.");
                }
                _logger.LogInformation("Successfully created OpenIddict Application shell for ClientId: {ClientId}", ApplicationInput.ClientId);

                // Now, link ProviderId if it's set and we are using custom entities
                if (ApplicationInput.ProviderId.HasValue && applicationObject is AppCustomOpenIddictApplication customApplication)
                {
                    // Verify the provider exists
                    var providerExists = await _dbContext.Providers.AnyAsync(p => p.Id == ApplicationInput.ProviderId.Value);
                    if (providerExists)
                    {
                        customApplication.ProviderId = ApplicationInput.ProviderId.Value;
                        await _applicationManager.UpdateAsync(customApplication); // Persist the ProviderId link
                        _logger.LogInformation("Linked application {ClientId} to ProviderId {ProviderId}", ApplicationInput.ClientId, ApplicationInput.ProviderId.Value);
                    }
                    else
                    {
                        _logger.LogWarning("ProviderId {ProviderId} selected for application {ClientId}, but Provider not found. Link not created.",
                            ApplicationInput.ProviderId.Value, ApplicationInput.ClientId);
                        // Optionally add a model error or handle this scenario
                    }
                }
                else if (ApplicationInput.ProviderId.HasValue && !(applicationObject is AppCustomOpenIddictApplication))
                {
                     _logger.LogWarning("Application {ClientId} was created but is not of type AppCustomOpenIddictApplication. Cannot link ProviderId {ProviderId}.",
                        ApplicationInput.ClientId, ApplicationInput.ProviderId.Value);
                }


                TempData["SuccessMessage"] = $"Application '{ApplicationInput.DisplayName}' ({ApplicationInput.ClientId}) created successfully.";
                return RedirectToPage("./Index");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating application {ClientId}.", ApplicationInput.ClientId);
                ModelState.AddModelError(string.Empty, $"An error occurred while creating the application: {ex.Message}");
                await PopulateSelectListsAsync();
                return Page();
            }
        }

       private async Task PopulateSelectListsAsync()
{
    ApplicationInput.AvailableClientTypes = new SelectList(new[]
    {
        new { Value = ClientTypes.Public, Text = "Public (e.g., SPAs, Mobile Apps - uses PKCE)" },
        new { Value = ClientTypes.Confidential, Text = "Confidential (e.g., Server-side Web Apps - uses Client Secret)" }
    }, "Value", "Text", ApplicationInput.ClientType);

    ApplicationInput.AvailableApplicationTypes = new SelectList(new[]
    {
        new SelectListItem { Value = "", Text = "(None)" }, // Allow not specifying
        new SelectListItem { Value = ApplicationTypes.Native, Text = "Native (Desktop/Mobile App)" },
        new SelectListItem { Value = ApplicationTypes.Web, Text = "Web Application (SPA or Server-side)" }
    }, "Value", "Text", ApplicationInput.ApplicationType);

    ApplicationInput.AvailableConsentTypes = new SelectList(new[]
    {
        new SelectListItem { Value = "", Text = "(Default - based on client type)" }, // OpenIddict defaults based on client type
        new SelectListItem { Value = ConsentTypes.Explicit, Text = "Explicit (User must always consent)" },
        new SelectListItem { Value = ConsentTypes.Implicit, Text = "Implicit (Consent implied if user signs in - for trusted first-party)" },
        new SelectListItem { Value = ConsentTypes.External, Text = "External (Consent managed externally, e.g., by admin)" },
        new SelectListItem { Value = ConsentTypes.Systematic, Text = "Systematic (Consent required once per scope combination)" }
    }, "Value", "Text", ApplicationInput.ConsentType);

    // --- Populate Permissions ---
    var permissions = new List<SelectListItem>();
    
    // Endpoints
    var endpointsGroup = new SelectListGroup { Name = "Endpoints" };
    foreach (var field in typeof(Permissions.Endpoints).GetFields().Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string)))
    {
        permissions.Add(new SelectListItem 
        { 
            Text = field.Name, 
            Value = (string)field.GetValue(null)!, 
            Group = endpointsGroup 
        });
    }
    
    // Grant Types
    var grantTypesGroup = new SelectListGroup { Name = "Grant Types" };
    foreach (var field in typeof(Permissions.GrantTypes).GetFields().Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string)))
    {
        permissions.Add(new SelectListItem 
        { 
            Text = field.Name, 
            Value = (string)field.GetValue(null)!, 
            Group = grantTypesGroup 
        });
    }
    
    // Response Types
    var responseTypesGroup = new SelectListGroup { Name = "Response Types" };
    foreach (var field in typeof(Permissions.ResponseTypes).GetFields().Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string)))
    {
        permissions.Add(new SelectListItem 
        { 
            Text = field.Name, 
            Value = (string)field.GetValue(null)!, 
            Group = responseTypesGroup 
        });
    }
    
    // Scopes (System-defined OIDC Scopes)
    var standardScopesGroup = new SelectListGroup { Name = "Standard Scopes" };
    foreach (var field in typeof(OpenIddictConstants.Scopes).GetFields().Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string)))
    {
        permissions.Add(new SelectListItem 
        { 
            Text = field.Name, 
            Value = Permissions.Prefixes.Scope + (string)field.GetValue(null)!, 
            Group = standardScopesGroup 
        });
    }
    
    // Custom Scopes (from database)
    var customScopesGroup = new SelectListGroup { Name = "Custom API Scopes" };
    await foreach(var scopeObject in _scopeManager.ListAsync())
    {
        var scopeName = await _scopeManager.GetNameAsync(scopeObject);
        if (!string.IsNullOrEmpty(scopeName) && !IsStandardOidcScope(scopeName))
        {
            permissions.Add(new SelectListItem 
            { 
                Text = scopeName, 
                Value = Permissions.Prefixes.Scope + scopeName, 
                Group = customScopesGroup 
            });
        }
    }
    
    ApplicationInput.AllAvailablePermissions = permissions;

    // --- Populate Requirements ---
    var requirements = new List<SelectListItem>();
    foreach (var field in typeof(Requirements).GetFields().Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string)))
    {
        requirements.Add(new SelectListItem 
        { 
            Text = field.Name, 
            Value = (string)field.GetValue(null)! 
        });
    }
    ApplicationInput.AllAvailableRequirements = requirements;

    // --- Populate Providers ---
    var providers = await _dbContext.Providers
                             .Where(p => p.IsActive)
                             .OrderBy(p => p.Name)
                             .Select(p => new { p.Id, p.Name })
                             .ToListAsync();
    ApplicationInput.AvailableProviders = new SelectList(providers, "Id", "Name", ApplicationInput.ProviderId);
}

        private bool IsStandardOidcScope(string scopeName)
        {
            return scopeName == OpenIddictConstants.Scopes.OpenId || scopeName == OpenIddictConstants.Scopes.Profile || scopeName == OpenIddictConstants.Scopes.Email ||
                   scopeName == OpenIddictConstants.Scopes.Phone || scopeName == OpenIddictConstants.Scopes.Address || scopeName == OpenIddictConstants.Scopes.Roles ||
                   scopeName == OpenIddictConstants.Scopes.OfflineAccess;
        }
    }
}