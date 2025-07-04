using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions; // For IOpenIddictScopeManager
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictScope
using System;
using System.Collections.Generic; // For List
using System.Collections.Immutable; // For ImmutableArray
using System.Linq; // For Any()
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Scopes
{
    /// <summary>
    /// This Razor Page model handles displaying the detailed information of a single OpenIddict scope.
    /// It provides a read-only view of all the scope's configured properties.
    /// </summary>
    /// <remarks>
    /// Authorization is handled by convention in `Program.cs`.
    /// </remarks>
    public class DetailsModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ILogger<DetailsModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="DetailsModel"/> class.
        /// </summary>
        /// <param name="scopeManager">The OpenIddict manager for scope entities.</param>
        /// <param name="logger">The logger for recording page operations.</param>
        public DetailsModel(IOpenIddictScopeManager scopeManager, ILogger<DetailsModel> logger)
        {
            _scopeManager = scopeManager;
            _logger = logger;
        }

        /// <summary>
        /// The view model holding the detailed scope data to be displayed on the page.
        /// </summary>
        public ScopeDetailsViewModel? Scope { get; set; }

        /// <summary>
        /// A view model specifically for displaying all details of a scope.
        /// </summary>
        public class ScopeDetailsViewModel
        {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? DisplayName { get; set; }
            public string? Description { get; set; }
            public ImmutableArray<string> Resources { get; set; }
            // Example of where a custom property would be displayed.
            // public bool RequiresElevatedConsent { get; set; }
        }

        /// <summary>
        /// Handles the GET request for the details page. It fetches all properties of the
        /// specified scope and populates the view model.
        /// </summary>
        /// <param name="id">The unique identifier of the scope to display.</param>
        /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
        public async Task<IActionResult> OnGetAsync(string? id, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Scope Details GET: ID is null or empty.");
                return NotFound("Scope ID not specified.");
            }

            var scopeObject = await _scopeManager.FindByIdAsync(id, cancellationToken);
            if (scopeObject == null || !(scopeObject is AppCustomOpenIddictScope customScope))
            {
                _logger.LogWarning("Scope Details GET: Scope with ID {ScopeId} not found or not of expected type.", id);
                return NotFound($"Scope with ID '{id}' not found or is not of the correct type.");
            }
            
            // Populate the detailed view model with all retrieved information.
            Scope = new ScopeDetailsViewModel
            {
                Id = await _scopeManager.GetIdAsync(customScope, cancellationToken),
                Name = await _scopeManager.GetNameAsync(customScope, cancellationToken),
                DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(customScope, cancellationToken),
                Description = await _scopeManager.GetLocalizedDescriptionAsync(customScope, cancellationToken),
                Resources = await _scopeManager.GetResourcesAsync(customScope, cancellationToken)
            };
            
            // Ensure the Resources array is not in a default (null) state for safe access in the view.
            if (Scope.Resources.IsDefault)
            {
                Scope.Resources = ImmutableArray<string>.Empty;
            }

            return Page();
        }
    }
}