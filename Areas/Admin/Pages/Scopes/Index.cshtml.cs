using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions; // For IOpenIddictScopeManager
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictScope
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Scopes
{
    /// <summary>
    /// This Razor Page model handles the listing of all registered OpenIddict scopes.
    /// It fetches all scopes from the database and displays them in a summary list.
    /// </summary>
    /// <remarks>
    /// Authorization is handled by convention in `Program.cs`.
    /// </remarks>
    public class IndexModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ILogger<IndexModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="IndexModel"/> class.
        /// </summary>
        /// <param name="scopeManager">The OpenIddict manager for scope entities.</param>
        /// <param name="logger">The logger for recording page operations.</param>
        public IndexModel(IOpenIddictScopeManager scopeManager, ILogger<IndexModel> logger)
        {
            _scopeManager = scopeManager;
            _logger = logger;
        }

        /// <summary>
        /// A list of scope summaries to be displayed in the main table.
        /// </summary>
        public IList<ScopeDisplayViewModel> Scopes { get;set; } = new List<ScopeDisplayViewModel>();

        /// <summary>
        /// A view model representing a summary of a scope for the index list.
        /// </summary>
        public class ScopeDisplayViewModel
        {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? DisplayName { get; set; }
            public string? Description { get; set; }
            public int ResourceCount { get; set; }
        }

        /// <summary>
        /// Handles the GET request for the index page. It retrieves all scopes
        /// from the database and populates the `Scopes` property.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
        public async Task OnGetAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Fetching list of OpenIddict scopes.");
            var scopesList = new List<ScopeDisplayViewModel>();
            const int scopesToFetch = 1000; // An arbitrary limit to prevent unbounded queries.

            // Iterate through the list of scopes provided by the manager.
            await foreach (var scopeObject in _scopeManager.ListAsync(count: scopesToFetch, offset: 0, cancellationToken: cancellationToken).WithCancellation(cancellationToken))
            {
                if (scopeObject is AppCustomOpenIddictScope customScope)
                {
                    var resources = await _scopeManager.GetResourcesAsync(customScope, cancellationToken);
                    
                    // Create a view model for each scope to display in the list.
                    scopesList.Add(new ScopeDisplayViewModel
                    {
                        Id = await _scopeManager.GetIdAsync(customScope, cancellationToken),
                        Name = await _scopeManager.GetNameAsync(customScope, cancellationToken),
                        DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(customScope, cancellationToken),
                        Description = await _scopeManager.GetLocalizedDescriptionAsync(customScope, cancellationToken),
                        ResourceCount = resources.Length
                    });
                }
                else if (scopeObject != null)
                {
                    _logger.LogWarning("Found scope of unexpected type: {Type}", scopeObject.GetType().FullName);
                }
            }
            // Order the scopes for consistent display.
            Scopes = scopesList.OrderBy(s => s.DisplayName ?? s.Name).ToList();
            _logger.LogInformation("Successfully fetched {ScopeCount} OpenIddict scopes.", Scopes.Count);
        }
    }
}