// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Applications/Edit.cshtml.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore; // For ToListAsync for Providers
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Orjnz.IdentityProvider.Web.Areas.Admin.Models; // For ApplicationViewModel
using Orjnz.IdentityProvider.Web.Data;             // For ApplicationDbContext, Provider
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json; // For JsonElement for properties/settings if needed
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Applications
{
    // Authorization handled by convention
    public class EditModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<EditModel> _logger;

        public EditModel(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            ApplicationDbContext dbContext,
            ILogger<EditModel> logger)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
            _dbContext = dbContext;
            _logger = logger;
        }

        [BindProperty]
        public ApplicationViewModel ApplicationInput { get; set; } = new ApplicationViewModel();

        public async Task<IActionResult> OnGetAsync(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Edit Application GET: ID is null or empty.");
                return NotFound("Application ID not specified.");
            }

            var applicationObject = await _applicationManager.FindByIdAsync(id);
            if (applicationObject == null || !(applicationObject is AppCustomOpenIddictApplication customApplication))
            {
                _logger.LogWarning("Edit Application GET: Application with ID {ApplicationId} not found or not of expected type.", id);
                return NotFound($"Application with ID '{id}' not found or is not of the correct custom type.");
            }

            // Populate ViewModel from the custom application entity
            ApplicationInput.Id = await _applicationManager.GetIdAsync(customApplication); // Should be same as input 'id'
            ApplicationInput.ClientId = await _applicationManager.GetClientIdAsync(customApplication) ?? string.Empty;
            ApplicationInput.DisplayName = await _applicationManager.GetDisplayNameAsync(customApplication) ?? string.Empty;
            ApplicationInput.ClientType = await _applicationManager.GetClientTypeAsync(customApplication) ?? ClientTypes.Public;
            ApplicationInput.ApplicationType = await _applicationManager.GetApplicationTypeAsync(customApplication);
            ApplicationInput.ConsentType = await _applicationManager.GetConsentTypeAsync(customApplication);

            ApplicationInput.SetRedirectUrisFromStringList(await _applicationManager.GetRedirectUrisAsync(customApplication));
            ApplicationInput.SetPostLogoutRedirectUrisFromStringList(await _applicationManager.GetPostLogoutRedirectUrisAsync(customApplication));

            ApplicationInput.SelectedPermissions = (await _applicationManager.GetPermissionsAsync(customApplication)).ToList();
            ApplicationInput.SelectedRequirements = (await _applicationManager.GetRequirementsAsync(customApplication)).ToList();

            ApplicationInput.ProviderId = customApplication.ProviderId;
            // ClientSecret is not typically displayed for edit, but if you allow changing it:
            // ApplicationInput.ClientSecret = "**********"; // Placeholder, don't display actual secret

            await PopulateSelectListsAsync();

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Trim string inputs
            ApplicationInput.ClientId = ApplicationInput.ClientId?.Trim() ?? string.Empty;
            ApplicationInput.DisplayName = ApplicationInput.DisplayName?.Trim() ?? string.Empty;
            ApplicationInput.ClientSecret = ApplicationInput.ClientSecret?.Trim(); // Null if empty, only used if changing

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Edit Application POST: Model state is invalid for Application ID {ApplicationId}.", ApplicationInput.Id);
                await PopulateSelectListsAsync(); // Repopulate dropdowns
                return Page();
            }

            if (string.IsNullOrEmpty(ApplicationInput.Id))
            {
                _logger.LogError("Edit Application POST: Application ID is missing from the input model.");
                ModelState.AddModelError(string.Empty, "Application identifier is missing. Cannot update.");
                await PopulateSelectListsAsync();
                return Page();
            }

            var applicationToUpdateObject = await _applicationManager.FindByIdAsync(ApplicationInput.Id);
            if (applicationToUpdateObject == null || !(applicationToUpdateObject is AppCustomOpenIddictApplication applicationToUpdate))
            {
                _logger.LogWarning("Edit Application POST: Application with ID {ApplicationId} not found during POST or not of expected type.", ApplicationInput.Id);
                return NotFound($"Application with ID '{ApplicationInput.Id}' not found.");
            }

            // Check for ClientId uniqueness if it has been changed
            var currentClientId = await _applicationManager.GetClientIdAsync(applicationToUpdate);
            if (currentClientId != ApplicationInput.ClientId)
            {
                if (await _applicationManager.FindByClientIdAsync(ApplicationInput.ClientId) != null)
                {
                    _logger.LogWarning("Edit Application POST: New ClientId '{NewClientId}' for Application ID {ApplicationId} already exists.", ApplicationInput.ClientId, ApplicationInput.Id);
                    ModelState.AddModelError(nameof(ApplicationViewModel.ClientId), "This Client ID is already in use by another application.");
                    await PopulateSelectListsAsync();
                    return Page();
                }
            }

            // Validate ClientSecret for confidential clients if it's being changed
            if (ApplicationInput.ClientType == ClientTypes.Confidential && 
                !string.IsNullOrWhiteSpace(ApplicationInput.ClientSecret) && // Only validate if a new secret is provided
                ApplicationInput.ClientSecret == "**********") // Check if it's the placeholder
            {
                // If placeholder is submitted, it means user didn't intend to change the secret
                ApplicationInput.ClientSecret = null; // Null it out so UpdateAsync doesn't try to update with "**********"
            }
            else if (ApplicationInput.ClientType == ClientTypes.Public && !string.IsNullOrEmpty(ApplicationInput.ClientSecret))
            {
                ApplicationInput.ClientSecret = null; // Public clients must not have a secret
            }


            // Create a descriptor to apply updates to the base OpenIddict properties
            var descriptor = new OpenIddictApplicationDescriptor();
            await _applicationManager.PopulateAsync(descriptor, applicationToUpdate); // Populate descriptor with existing values

            // Apply changes from ViewModel to descriptor
            descriptor.ClientId = ApplicationInput.ClientId;
            descriptor.DisplayName = ApplicationInput.DisplayName;
            descriptor.ClientType = ApplicationInput.ClientType;
            descriptor.ApplicationType = ApplicationInput.ApplicationType;
            descriptor.ConsentType = ApplicationInput.ConsentType;

            // If a new client secret is provided (and not the placeholder), it will be hashed by UpdateAsync.
            // If ClientSecret is null or empty, existing secret is preserved unless changing client type from confidential.
            if (!string.IsNullOrWhiteSpace(ApplicationInput.ClientSecret))
            {
                descriptor.ClientSecret = ApplicationInput.ClientSecret;
            }
            else if (descriptor.ClientType == ClientTypes.Public && !string.IsNullOrEmpty(descriptor.ClientSecret))
            {
                // If changing to public and a secret was previously set, clear it
                descriptor.ClientSecret = null;
            }


            descriptor.RedirectUris.Clear(); 
descriptor.RedirectUris.UnionWith(ApplicationInput.GetRedirectUrisAsImmutableArray());

descriptor.PostLogoutRedirectUris.Clear(); 
descriptor.PostLogoutRedirectUris.UnionWith(ApplicationInput.GetPostLogoutRedirectUrisAsImmutableArray());

descriptor.Permissions.Clear(); 
descriptor.Permissions.UnionWith(ApplicationInput.SelectedPermissions);

descriptor.Requirements.Clear(); 
descriptor.Requirements.UnionWith(ApplicationInput.SelectedRequirements);

            // Handle custom properties/settings if any were part of ApplicationViewModel and editable
            // descriptor.Properties.Clear();
            // descriptor.Properties["some_prop"] = System.Text.Json.JsonSerializer.SerializeToElement("new_value");


            try
            {
                // Update the base OpenIddict application properties
                await _applicationManager.UpdateAsync(applicationToUpdate, descriptor);
                _logger.LogInformation("Successfully updated base properties for Application ID: {ApplicationId}", ApplicationInput.Id);

                // Update the custom ProviderId property on our AppCustomOpenIddictApplication entity
                // This needs to be done directly on the entity and then saved via the manager or DbContext.
                // Since _applicationManager.UpdateAsync takes the entity, if it's our custom type, it might save all changes.
                // Or, we might need a separate DbContext save if ProviderId is not handled by OpenIddict's UpdateAsync.

                bool providerIdChanged = applicationToUpdate.ProviderId != ApplicationInput.ProviderId;
                if (providerIdChanged)
                {
                    if (ApplicationInput.ProviderId.HasValue)
                    {
                        var providerExists = await _dbContext.Providers.AnyAsync(p => p.Id == ApplicationInput.ProviderId.Value);
                        if (providerExists)
                        {
                            applicationToUpdate.ProviderId = ApplicationInput.ProviderId.Value;
                        }
                        else
                        {
                            _logger.LogWarning("Selected ProviderId {ProviderId} for application {ClientId} does not exist. Link not updated.",
                                ApplicationInput.ProviderId.Value, ApplicationInput.ClientId);
                            ModelState.AddModelError(nameof(ApplicationViewModel.ProviderId), "The selected provider does not exist.");
                            await PopulateSelectListsAsync();
                            return Page();
                        }
                    }
                    else // ProviderId is being cleared
                    {
                        applicationToUpdate.ProviderId = null;
                    }
                    // The UpdateAsync above should ideally persist this change if applicationToUpdate is the tracked entity.
                    // If OpenIddict's UpdateAsync doesn't save custom properties on the entity itself,
                    // an explicit DbContext.SaveChanges might be needed, or ensure the manager can handle it.
                    // For OpenIddict with EF Core, if 'applicationToUpdate' is the tracked entity from FindByIdAsync,
                    // changes to its direct properties like ProviderId should be saved by UpdateAsync if the manager
                    // is aware of the custom type.
                    await _applicationManager.UpdateAsync(applicationToUpdate); // Call update again IF ProviderId is not part of descriptor model
                                                                          // This second call might be redundant if the first UpdateAsync saves all changes on AppCustomOpenIddictApplication.
                                                                          // It's safer to assume the first UpdateAsync handles descriptor properties,
                                                                          // and if custom entity properties were modified directly on 'applicationToUpdate',
                                                                          // that same UpdateAsync call (or a subsequent one if needed) should persist them.
                                                                          // Given EF Core, if `applicationToUpdate` is tracked, changes to ProviderId are noted.
                                                                          // The `UpdateAsync(entity, descriptor)` merges descriptor into entity.
                                                                          // The `UpdateAsync(entity)` persists the entity state.
                    _logger.LogInformation("Updated ProviderId for application {ClientId} to {ProviderId}", ApplicationInput.ClientId, applicationToUpdate.ProviderId);
                }


                TempData["SuccessMessage"] = $"Application '{ApplicationInput.DisplayName}' ({ApplicationInput.ClientId}) updated successfully.";
                return RedirectToPage("./Index");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating application {ClientId}.", ApplicationInput.ClientId);
                ModelState.AddModelError(string.Empty, $"An error occurred while updating the application: {ex.Message}");
                await PopulateSelectListsAsync();
                return Page();
            }
        }

        // Re-use the PopulateSelectListsAsync method from CreateModel (can be moved to a shared base class or service)
        private async Task PopulateSelectListsAsync()
        {
            ApplicationInput.AvailableClientTypes = new SelectList(new[]
            {
                new { Value = ClientTypes.Public, Text = "Public (e.g., SPAs, Mobile Apps - uses PKCE)" },
                new { Value = ClientTypes.Confidential, Text = "Confidential (e.g., Server-side Web Apps - uses Client Secret)" }
            }, "Value", "Text", ApplicationInput.ClientType);

            ApplicationInput.AvailableApplicationTypes = new SelectList(new[]
            {
                new SelectListItem { Value = "", Text = "(None)" },
                new SelectListItem { Value = ApplicationTypes.Native, Text = "Native (Desktop/Mobile App)" },
                new SelectListItem { Value = ApplicationTypes.Web, Text = "Web Application (SPA or Server-side)" }
            }, "Value", "Text", ApplicationInput.ApplicationType);

            ApplicationInput.AvailableConsentTypes = new SelectList(new[]
            {
                new SelectListItem { Value = "", Text = "(Default - based on client type)" },
                new SelectListItem { Value = ConsentTypes.Explicit, Text = "Explicit (User must always consent)" },
                new SelectListItem { Value = ConsentTypes.Implicit, Text = "Implicit (Consent implied)" },
                new SelectListItem { Value = ConsentTypes.External, Text = "External (Admin pre-approved)" },
                new SelectListItem { Value = ConsentTypes.Systematic, Text = "Systematic (Consent once per scope combo)" }
            }, "Value", "Text", ApplicationInput.ConsentType);

            var permissions = new List<SelectListItem>();
            var endpointsGroup = new SelectListGroup { Name = "Endpoints" };
            foreach (var field in typeof(Permissions.Endpoints).GetFields().Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string)))
                permissions.Add(new SelectListItem { Text = field.Name, Value = (string)field.GetValue(null)!, Group = endpointsGroup });
            
            var grantTypesGroup = new SelectListGroup { Name = "Grant Types" };
            foreach (var field in typeof(Permissions.GrantTypes).GetFields().Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string)))
                permissions.Add(new SelectListItem { Text = field.Name, Value = (string)field.GetValue(null)!, Group = grantTypesGroup });
            
            var responseTypesGroup = new SelectListGroup { Name = "Response Types" };
            foreach (var field in typeof(Permissions.ResponseTypes).GetFields().Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string)))
                permissions.Add(new SelectListItem { Text = field.Name, Value = (string)field.GetValue(null)!, Group = responseTypesGroup });
            
            var standardScopesGroup = new SelectListGroup { Name = "Standard Scopes" };
            foreach (var field in typeof(OpenIddictConstants.Scopes).GetFields().Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string)))
                permissions.Add(new SelectListItem { Text = field.Name, Value = Permissions.Prefixes.Scope + (string)field.GetValue(null)!, Group = standardScopesGroup });
            
            var customScopesGroup = new SelectListGroup { Name = "Custom API Scopes" };
            await foreach(var scopeObject in _scopeManager.ListAsync())
            {
                var scopeName = await _scopeManager.GetNameAsync(scopeObject);
                if (!string.IsNullOrEmpty(scopeName) && !IsStandardOidcScope(scopeName))
                    permissions.Add(new SelectListItem { Text = scopeName, Value = Permissions.Prefixes.Scope + scopeName, Group = customScopesGroup });
            }
            ApplicationInput.AllAvailablePermissions = permissions.OrderBy(p => p.Group?.Name).ThenBy(p => p.Text).ToList();

            var requirements = new List<SelectListItem>();
            foreach (var field in typeof(Requirements).GetFields().Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string)))
                requirements.Add(new SelectListItem { Text = field.Name, Value = (string)field.GetValue(null)! });
            ApplicationInput.AllAvailableRequirements = requirements.OrderBy(r => r.Text).ToList();

            var providers = await _dbContext.Providers
                                     .Where(p => p.IsActive) // Or all providers for selection, even inactive ones
                                     .OrderBy(p => p.Name)
                                     .Select(p => new { Id = p.Id.ToString(), p.Name }) // Ensure Id is string for SelectList
                                     .ToListAsync();
            ApplicationInput.AvailableProviders = new SelectList(providers, "Id", "Name", ApplicationInput.ProviderId?.ToString());
        }
        
        private bool IsStandardOidcScope(string scopeName)
        {
            return scopeName == OpenIddictConstants.Scopes.OpenId || scopeName == OpenIddictConstants.Scopes.Profile || scopeName == OpenIddictConstants.Scopes.Email ||
                   scopeName == OpenIddictConstants.Scopes.Phone || scopeName ==OpenIddictConstants.Scopes.Address || scopeName == OpenIddictConstants.Scopes.Roles ||
                   scopeName == OpenIddictConstants.Scopes.OfflineAccess;
        }
    }
}