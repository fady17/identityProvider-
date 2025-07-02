// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Scopes/Edit.cshtml.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions; // For IOpenIddictScopeManager, OpenIddictScopeDescriptor, Constants
using Orjnz.IdentityProvider.Web.Areas.Admin.Models; // For ScopeViewModel
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictScope
using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Tasks;
// using static OpenIddict.Abstractions.OpenIddictConstants; // Not strictly needed here for constants

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Scopes
{
    // Authorization handled by convention
    public class EditModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ILogger<EditModel> _logger;

        public EditModel(IOpenIddictScopeManager scopeManager, ILogger<EditModel> logger)
        {
            _scopeManager = scopeManager;
            _logger = logger;
        }

        [BindProperty]
        public ScopeViewModel ScopeInput { get; set; } = new ScopeViewModel();

        public async Task<IActionResult> OnGetAsync(string? id, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Edit Scope GET: ID is null or empty.");
                return NotFound("Scope ID not specified.");
            }

            var scopeObject = await _scopeManager.FindByIdAsync(id, cancellationToken);
            if (scopeObject == null || !(scopeObject is AppCustomOpenIddictScope customScope))
            {
                _logger.LogWarning("Edit Scope GET: Scope with ID {ScopeId} not found or not of expected type.", id);
                return NotFound($"Scope with ID '{id}' not found or is not of the correct custom type.");
            }

            // Populate ViewModel from the scope entity
            ScopeInput.Id = await _scopeManager.GetIdAsync(customScope, cancellationToken);
            ScopeInput.Name = await _scopeManager.GetNameAsync(customScope, cancellationToken) ?? string.Empty;
            ScopeInput.DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(customScope, cancellationToken);
            ScopeInput.Description = await _scopeManager.GetLocalizedDescriptionAsync(customScope, cancellationToken);
            
            var resources = await _scopeManager.GetResourcesAsync(customScope, cancellationToken);
            ScopeInput.Resources = resources.Any() ? string.Join(Environment.NewLine, resources) : null;

            // If AppCustomOpenIddictScope had custom properties, load them here
            // ScopeInput.RequiresElevatedConsent = customScope.RequiresElevatedConsent; // Example

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
        {
            // Trim string inputs
            ScopeInput.Name = ScopeInput.Name?.Trim() ?? string.Empty;
            ScopeInput.DisplayName = ScopeInput.DisplayName?.Trim();
            ScopeInput.Description = ScopeInput.Description?.Trim();
            ScopeInput.Resources = ScopeInput.Resources?.Trim();

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Edit Scope POST: Model state is invalid for Scope ID {ScopeId}.", ScopeInput.Id);
                return Page(); // Re-display form with validation errors
            }

            if (string.IsNullOrEmpty(ScopeInput.Id))
            {
                _logger.LogError("Edit Scope POST: Scope ID is missing from the input model.");
                ModelState.AddModelError(string.Empty, "Scope identifier is missing. Cannot update.");
                return Page();
            }

            var scopeToUpdateObject = await _scopeManager.FindByIdAsync(ScopeInput.Id, cancellationToken);
            if (scopeToUpdateObject == null || !(scopeToUpdateObject is AppCustomOpenIddictScope scopeToUpdate))
            {
                _logger.LogWarning("Edit Scope POST: Scope with ID {ScopeId} not found during POST or not of expected type.", ScopeInput.Id);
                return NotFound($"Scope with ID '{ScopeInput.Id}' not found.");
            }

            // Check for Scope Name uniqueness if it has been changed
            var currentName = await _scopeManager.GetNameAsync(scopeToUpdate, cancellationToken);
            if (currentName != ScopeInput.Name)
            {
                if (await _scopeManager.FindByNameAsync(ScopeInput.Name, cancellationToken) != null)
                {
                    _logger.LogWarning("Edit Scope POST: New Name '{NewName}' for Scope ID {ScopeId} already exists.", ScopeInput.Name, ScopeInput.Id);
                    ModelState.AddModelError(nameof(ScopeViewModel.Name), "This Scope Name is already in use by another scope.");
                    return Page();
                }
            }

            // Create a descriptor to apply updates
            var descriptor = new OpenIddictScopeDescriptor();
            // Populate descriptor with existing values from the entity first
            await _scopeManager.PopulateAsync(descriptor, scopeToUpdate, cancellationToken);

            // Apply changes from ViewModel to descriptor
            descriptor.Name = ScopeInput.Name; // Name can be updated, though often discouraged if in use
            descriptor.DisplayName = ScopeInput.DisplayName;
            descriptor.Description = ScopeInput.Description;

            descriptor.Resources.Clear(); // Clear existing resources on descriptor before adding new ones
            if (!string.IsNullOrWhiteSpace(ScopeInput.Resources))
            {
                var resources = ScopeInput.Resources
                                    .Split(new[] { '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                    .Where(r => !string.IsNullOrWhiteSpace(r))
                                    .Distinct(StringComparer.OrdinalIgnoreCase)
                                    .ToImmutableArray();
                if (resources.Any())
                {
                    descriptor.Resources.UnionWith(resources);
                }
            }
            
            // If AppCustomOpenIddictScope had custom properties NOT on OpenIddictScopeDescriptor,
            // you'd update them directly on the 'scopeToUpdate' entity before calling UpdateAsync(entity).
            // scopeToUpdate.RequiresElevatedConsent = ScopeInput.RequiresElevatedConsent; // Example

            try
            {
                // Update using the entity and the descriptor
                await _scopeManager.UpdateAsync(scopeToUpdate, descriptor, cancellationToken);
                _logger.LogInformation("Successfully updated Scope: {ScopeName} (ID: {ScopeId})", ScopeInput.Name, ScopeInput.Id);

                TempData["SuccessMessage"] = $"Scope '{ScopeInput.Name}' updated successfully.";
                return RedirectToPage("./Index");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating scope {ScopeName} (ID: {ScopeId}).", ScopeInput.Name, ScopeInput.Id);
                ModelState.AddModelError(string.Empty, $"An error occurred while updating the scope: {ex.Message}");
                return Page();
            }
        }
    }
}