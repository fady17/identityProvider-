// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Scopes/Create.cshtml.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions; // For IOpenIddictScopeManager, OpenIddictScopeDescriptor, Constants
using Orjnz.IdentityProvider.Web.Areas.Admin.Models; // For ScopeViewModel
using System;
using System.Collections.Immutable; // For ImmutableArray
using System.Linq; // For Any()
using System.Threading.Tasks;
// using static OpenIddict.Abstractions.OpenIddictConstants; // Not strictly needed here unless using constants directly

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Scopes
{
    // Authorization handled by convention in Program.cs
    public class CreateModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ILogger<CreateModel> _logger;

        public CreateModel(IOpenIddictScopeManager scopeManager, ILogger<CreateModel> logger)
        {
            _scopeManager = scopeManager;
            _logger = logger;
        }

        [BindProperty]
        public ScopeViewModel ScopeInput { get; set; } = new ScopeViewModel();

        public IActionResult OnGet()
        {
            // Initialize any default values for the form if needed
            // For example, if you had a custom property on AppCustomOpenIddictScope
            // ScopeInput.RequiresElevatedConsent = false;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
        {
            // Trim string inputs
            ScopeInput.Name = ScopeInput.Name?.Trim() ?? string.Empty;
            ScopeInput.DisplayName = ScopeInput.DisplayName?.Trim(); // Can be null
            ScopeInput.Description = ScopeInput.Description?.Trim(); // Can be null
            ScopeInput.Resources = ScopeInput.Resources?.Trim(); // Can be null, will be split later

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Create Scope POST: Model state is invalid.");
                return Page(); // Re-display form with validation errors
            }

            // Check for Scope Name uniqueness
            if (await _scopeManager.FindByNameAsync(ScopeInput.Name, cancellationToken) != null)
            {
                _logger.LogWarning("Create Scope POST: Scope name '{ScopeName}' already exists.", ScopeInput.Name);
                ModelState.AddModelError(nameof(ScopeViewModel.Name), "This Scope Name is already in use. Please choose another.");
                return Page();
            }

            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = ScopeInput.Name,
                DisplayName = ScopeInput.DisplayName, // Can be null if not provided
                Description = ScopeInput.Description  // Can be null if not provided
            };

            // Process resources (audiences)
            if (!string.IsNullOrWhiteSpace(ScopeInput.Resources))
            {
                var resources = ScopeInput.Resources
                                    .Split(new[] { '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                    .Where(r => !string.IsNullOrWhiteSpace(r))
                                    .Distinct(StringComparer.OrdinalIgnoreCase) // Avoid duplicate resources
                                    .ToImmutableArray();

                if (resources.Any())
                {
                    descriptor.Resources.UnionWith(resources);
                }
            }

            // If you had custom properties on AppCustomOpenIddictScope, you'd try to set them on the descriptor
            // if the descriptor supports them, or handle them after creation if using custom entity directly.
            // OpenIddictScopeDescriptor is fairly standard, so custom properties are usually handled by
            // creating the object and then updating your custom entity instance.
            // However, for properties OpenIddict knows about (like DisplayName, Description, Resources),
            // setting them on the descriptor is correct.

            try
            {
                var scopeObject = await _scopeManager.CreateAsync(descriptor, cancellationToken);
                if (scopeObject == null)
                {
                    // This would be unusual if CreateAsync doesn't throw on failure
                    throw new InvalidOperationException("Scope creation returned null.");
                }
                _logger.LogInformation("Successfully created Scope: {ScopeName}", ScopeInput.Name);

                // If you had custom properties on AppCustomOpenIddictScope that are not on OpenIddictScopeDescriptor:
                // if (scopeObject is AppCustomOpenIddictScope customScope)
                // {
                //     customScope.RequiresElevatedConsent = ScopeInput.RequiresElevatedConsent; // Example
                //     await _scopeManager.UpdateAsync(customScope, cancellationToken);
                //     _logger.LogInformation("Updated custom properties for Scope: {ScopeName}", ScopeInput.Name);
                // }

                TempData["SuccessMessage"] = $"Scope '{ScopeInput.Name}' created successfully.";
                return RedirectToPage("./Index");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating scope '{ScopeName}'.", ScopeInput.Name);
                ModelState.AddModelError(string.Empty, $"An error occurred while creating the scope: {ex.Message}");
                return Page();
            }
        }
    }
}