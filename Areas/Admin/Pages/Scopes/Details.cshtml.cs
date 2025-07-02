// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Scopes/Details.cshtml.cs
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
    // Authorization handled by convention
    public class DetailsModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ILogger<DetailsModel> _logger;

        public DetailsModel(IOpenIddictScopeManager scopeManager, ILogger<DetailsModel> logger)
        {
            _scopeManager = scopeManager;
            _logger = logger;
        }

        public ScopeDetailsViewModel? Scope { get; set; }

        public class ScopeDetailsViewModel
        {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? DisplayName { get; set; }
            public string? Description { get; set; }
            public ImmutableArray<string> Resources { get; set; }
            // Add any custom properties from AppCustomOpenIddictScope here
            // public bool RequiresElevatedConsent { get; set; } // Example
        }

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
                return NotFound($"Scope with ID '{id}' not found or is not of the correct custom type.");
            }

            Scope = new ScopeDetailsViewModel
            {
                Id = await _scopeManager.GetIdAsync(customScope, cancellationToken),
                Name = await _scopeManager.GetNameAsync(customScope, cancellationToken),
                DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(customScope, cancellationToken),
                Description = await _scopeManager.GetLocalizedDescriptionAsync(customScope, cancellationToken),
                Resources = await _scopeManager.GetResourcesAsync(customScope, cancellationToken)
                // RequiresElevatedConsent = customScope.RequiresElevatedConsent // Example for custom prop
            };

            if (Scope.Resources.IsDefault) // Ensure it's not a 'null' ImmutableArray
            {
                Scope.Resources = ImmutableArray<string>.Empty;
            }


            return Page();
        }
    }
}