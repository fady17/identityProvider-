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
    /// <summary>
    /// This Razor Page model handles the creation of new OpenIddict scopes. Scopes represent
    /// permissions that client applications can request (e.g., 'openid', 'profile', 'api:read').
    /// </summary>
    /// <remarks>
    /// Authorization for this page is handled by convention in `Program.cs`.
    /// </remarks>
    public class CreateModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ILogger<CreateModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CreateModel"/> class.
        /// </summary>
        /// <param name="scopeManager">The OpenIddict manager for scope entities.</param>
        /// <param name="logger">The logger for recording page operations.</param>
        public CreateModel(IOpenIddictScopeManager scopeManager, ILogger<CreateModel> logger)
        {
            _scopeManager = scopeManager;
            _logger = logger;
        }

        /// <summary>
        /// The view model that binds to the create scope form.
        /// </summary>
        [BindProperty]
        public ScopeViewModel ScopeInput { get; set; } = new ScopeViewModel();

        /// <summary>
        /// Handles the GET request to display the create scope form.
        /// </summary>
        public IActionResult OnGet()
        {
            // This method can be used to initialize any default values for the form.
            return Page();
        }

        /// <summary>
        /// Handles the POST request to create a new scope. It validates the input,
        /// checks for name uniqueness, and uses the OpenIddict manager to persist the new scope.
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
                _logger.LogWarning("Create Scope POST: Model state is invalid.");
                return Page(); // Re-display the form with validation errors.
            }

            // Ensure the scope name is unique.
            if (await _scopeManager.FindByNameAsync(ScopeInput.Name, cancellationToken) != null)
            {
                _logger.LogWarning("Create Scope POST: Scope name '{ScopeName}' already exists.", ScopeInput.Name);
                ModelState.AddModelError(nameof(ScopeViewModel.Name), "This Scope Name is already in use. Please choose another.");
                return Page();
            }

            // --- 2. Create Scope Descriptor ---
            // The descriptor is a temporary object used to define the properties of the new scope.
            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = ScopeInput.Name,
                DisplayName = ScopeInput.DisplayName,
                Description = ScopeInput.Description
            };

            // Process the associated resources (audiences) from the textarea input.
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
            
            // --- 3. Persist Scope ---
            try
            {
                // Use the manager to create the scope in the database from the descriptor.
                var scopeObject = await _scopeManager.CreateAsync(descriptor, cancellationToken);
                if (scopeObject == null)
                {
                    throw new InvalidOperationException("Scope creation returned null.");
                }
                _logger.LogInformation("Successfully created Scope: {ScopeName}", ScopeInput.Name);

                // This is an extension point. If our custom scope entity had properties not
                // supported by the standard descriptor, we would cast the created object here
                // and update those properties separately.
                // e.g., if (scopeObject is AppCustomOpenIddictScope customScope) { ... }

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