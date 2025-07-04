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
    /// <summary>
    /// This Razor Page model handles the editing of an existing OpenIddict scope.
    /// It populates a form with the scope's current data and processes the
    /// submission to apply updates to the database.
    /// </summary>
    /// <remarks>
    /// Authorization is handled by convention in `Program.cs`.
    /// </remarks>
    public class EditModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ILogger<EditModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="EditModel"/> class.
        /// </summary>
        /// <param name="scopeManager">The OpenIddict manager for scope entities.</param>
        /// <param name="logger">The logger for recording page operations.</param>
        public EditModel(IOpenIddictScopeManager scopeManager, ILogger<EditModel> logger)
        {
            _scopeManager = scopeManager;
            _logger = logger;
        }

        /// <summary>
        /// The view model that binds to the edit scope form.
        /// </summary>
        [BindProperty]
        public ScopeViewModel ScopeInput { get; set; } = new ScopeViewModel();

        /// <summary>
        /// Handles the GET request for the edit page. It fetches the existing scope's
        /// data and populates the view model for the form.
        /// </summary>
        /// <param name="id">The unique identifier of the scope to edit.</param>
        /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
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

            // Populate the view model from the retrieved database entity.
            ScopeInput.Id = await _scopeManager.GetIdAsync(customScope, cancellationToken);
            ScopeInput.Name = await _scopeManager.GetNameAsync(customScope, cancellationToken) ?? string.Empty;
            ScopeInput.DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(customScope, cancellationToken);
            ScopeInput.Description = await _scopeManager.GetLocalizedDescriptionAsync(customScope, cancellationToken);
            
            var resources = await _scopeManager.GetResourcesAsync(customScope, cancellationToken);
            // Convert the collection of resources into a single newline-separated string for the textarea.
            ScopeInput.Resources = resources.Any() ? string.Join(Environment.NewLine, resources) : null;

            // If AppCustomOpenIddictScope had custom properties, they would be loaded here.
            // Example: ScopeInput.RequiresElevatedConsent = customScope.RequiresElevatedConsent;

            return Page();
        }

        /// <summary>
        /// Handles the POST request from the form submission to apply updates to the scope.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
        public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
        {
            // --- 1. Data Cleaning and Validation ---
            ScopeInput.Name = ScopeInput.Name?.Trim() ?? string.Empty;
            ScopeInput.DisplayName = ScopeInput.DisplayName?.Trim();
            ScopeInput.Description = ScopeInput.Description?.Trim();
            ScopeInput.Resources = ScopeInput.Resources?.Trim();

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Edit Scope POST: Model state is invalid for Scope ID {ScopeId}.", ScopeInput.Id);
                return Page(); // Re-display the form with validation errors.
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

            // If the scope name was changed, ensure the new name is not already in use.
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

            // --- 2. Update Scope using Descriptor ---
            // The recommended pattern for updating OpenIddict entities is to populate a descriptor
            // with existing values, apply changes, and then call the manager's update method.
            var descriptor = new OpenIddictScopeDescriptor();
            await _scopeManager.PopulateAsync(descriptor, scopeToUpdate, cancellationToken);

            // Apply changes from the view model to the descriptor.
            descriptor.Name = ScopeInput.Name;
            descriptor.DisplayName = ScopeInput.DisplayName;
            descriptor.Description = ScopeInput.Description;

            descriptor.Resources.Clear(); // Clear existing resources on the descriptor before adding the new set.
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
            
            // If custom properties were on the entity, they would be updated directly on the `scopeToUpdate` object here.

            // --- 3. Persist Changes ---
            try
            {
                // Update the entity in the database using the modified descriptor.
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