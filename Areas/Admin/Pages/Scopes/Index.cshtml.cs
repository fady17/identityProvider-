// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Scopes/Index.cshtml.cs
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
    // Authorization handled by convention
    public class IndexModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(IOpenIddictScopeManager scopeManager, ILogger<IndexModel> logger)
        {
            _scopeManager = scopeManager;
            _logger = logger;
        }

        public IList<ScopeDisplayViewModel> Scopes { get;set; } = new List<ScopeDisplayViewModel>();

        public class ScopeDisplayViewModel
        {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? DisplayName { get; set; }
            public string? Description { get; set; }
            public int ResourceCount { get; set; }
        }

        public async Task OnGetAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Fetching list of OpenIddict scopes.");
            var scopesList = new List<ScopeDisplayViewModel>();
            const int scopesToFetch = 1000; // Adjust or implement paging for large number of scopes

            await foreach (var scopeObject in _scopeManager.ListAsync(count: scopesToFetch, offset: 0, cancellationToken: cancellationToken)
                                                        .WithCancellation(cancellationToken))
            {
                // Assuming scopeObject is AppCustomOpenIddictScope due to ReplaceDefaultEntities
                if (scopeObject is AppCustomOpenIddictScope customScope)
                {
                    var resources = await _scopeManager.GetResourcesAsync(customScope, cancellationToken);
                    scopesList.Add(new ScopeDisplayViewModel
                    {
                        Id = await _scopeManager.GetIdAsync(customScope, cancellationToken),
                        Name = await _scopeManager.GetNameAsync(customScope, cancellationToken),
                        DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(customScope, cancellationToken), // Handles null DisplayName
                        Description = await _scopeManager.GetLocalizedDescriptionAsync(customScope, cancellationToken),
                        ResourceCount = resources.Length
                    });
                }
                else if (scopeObject != null)
                {
                    _logger.LogWarning("Found scope of unexpected type: {Type}", scopeObject.GetType().FullName);
                }
            }
            Scopes = scopesList.OrderBy(s => s.DisplayName ?? s.Name).ToList();
            _logger.LogInformation("Successfully fetched {ScopeCount} OpenIddict scopes.", Scopes.Count);
        }
    }
}