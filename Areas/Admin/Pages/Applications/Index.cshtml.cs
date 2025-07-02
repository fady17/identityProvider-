// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Applications/Index.cshtml.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore; // For ToListAsync on IQueryable
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions; // For IOpenIddictApplicationManager
using Orjnz.IdentityProvider.Web.Data; // For ApplicationDbContext (to get Provider name if filtering)
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Applications
{
    // Authorization handled by convention in Program.cs
    public class IndexModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ApplicationDbContext _dbContext; // To fetch Provider name for filter display
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(
            IOpenIddictApplicationManager applicationManager,
            ApplicationDbContext dbContext,
            ILogger<IndexModel> logger)
        {
            _applicationManager = applicationManager;
            _dbContext = dbContext;
            _logger = logger;
        }

        public IList<ApplicationSummaryViewModel> Applications { get; set; } = new List<ApplicationSummaryViewModel>();

        [BindProperty(SupportsGet = true)] // To bind from query string e.g., ?filterByProviderId=...
        public Guid? FilterByProviderId { get; set; }

        public string? ProviderFilterName { get; set; } // To display the name of the provider being filtered by

        // ViewModel for displaying application summaries in the list
        public class ApplicationSummaryViewModel
        {
            public string? Id { get; set; } // OpenIddict Application ID (string)
            public string? ClientId { get; set; }
            public string? DisplayName { get; set; }
            public string? ClientType { get; set; }
            public string? ApplicationType { get; set; }
            public Guid? ProviderId { get; set; } // To know if it's linked
            public string? ProviderName { get; set; } // Display name of the linked provider
            public int RedirectUriCount { get; set; }
            public int PostLogoutRedirectUriCount { get; set; }
        }

        public async Task OnGetAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Fetching list of client applications. FilterByProviderId: {FilterProviderId}", FilterByProviderId);

            var applicationsList = new List<ApplicationSummaryViewModel>();
            long totalApplications = await _applicationManager.CountAsync(cancellationToken);
            const int applicationsToFetch = 1000; // Arbitrary limit for ListAsync, adjust if needed or implement paging

            // First, collect all applications into a list to avoid the async enumerable issue
            var allApplications = new List<AppCustomOpenIddictApplication>();
            
            await foreach (var appObject in _applicationManager.ListAsync(count: applicationsToFetch, offset: 0, cancellationToken: cancellationToken)
                                                            .WithCancellation(cancellationToken))
            {
                if (appObject is AppCustomOpenIddictApplication customApp)
                {
                    // Apply filter if ProviderId is specified
                    if (FilterByProviderId.HasValue && customApp.ProviderId != FilterByProviderId.Value)
                    {
                        continue; // Skip this application if it doesn't match the filter
                    }

                    allApplications.Add(customApp);
                }
                else if (appObject != null)
                {
                    _logger.LogWarning("Found application of unexpected type: {Type}", appObject.GetType().FullName);
                }
            }

            // Get all unique provider IDs to batch load provider names
            var providerIds = allApplications
                .Where(app => app.ProviderId.HasValue)
                .Select(app => app.ProviderId!.Value)
                .Distinct()
                .ToList();

            // Batch load provider names to avoid N+1 queries
            var providerNames = new Dictionary<Guid, string>();
            if (providerIds.Any())
            {
                var providers = await _dbContext.Providers
                    .Where(p => providerIds.Contains(p.Id))
                    .Select(p => new { p.Id, p.Name })
                    .ToDictionaryAsync(p => p.Id, p => p.Name, cancellationToken);
                
                providerNames = providers;
            }

            // Now process each application without making additional async calls during enumeration
            foreach (var customApp in allApplications)
            {
                string? providerName = null;
                if (customApp.ProviderId.HasValue && providerNames.TryGetValue(customApp.ProviderId.Value, out var name))
                {
                    providerName = name;
                }

                var redirectUris = await _applicationManager.GetRedirectUrisAsync(customApp, cancellationToken);
                var postLogoutRedirectUris = await _applicationManager.GetPostLogoutRedirectUrisAsync(customApp, cancellationToken);

                applicationsList.Add(new ApplicationSummaryViewModel
                {
                    Id = await _applicationManager.GetIdAsync(customApp, cancellationToken),
                    ClientId = await _applicationManager.GetClientIdAsync(customApp, cancellationToken),
                    DisplayName = await _applicationManager.GetDisplayNameAsync(customApp, cancellationToken),
                    ClientType = await _applicationManager.GetClientTypeAsync(customApp, cancellationToken),
                    ApplicationType = await _applicationManager.GetApplicationTypeAsync(customApp, cancellationToken),
                    ProviderId = customApp.ProviderId,
                    ProviderName = providerName,
                    RedirectUriCount = redirectUris.Length,
                    PostLogoutRedirectUriCount = postLogoutRedirectUris.Length
                });
            }

            Applications = applicationsList.OrderBy(a => a.DisplayName).ToList();

            // Load provider filter name if needed
            if (FilterByProviderId.HasValue)
            {
                if (providerNames.TryGetValue(FilterByProviderId.Value, out var filterProviderName))
                {
                    ProviderFilterName = filterProviderName;
                }
                else
                {
                    // Fallback if provider wasn't in the batch load (shouldn't happen normally)
                    var provider = await _dbContext.Providers.FindAsync(new object[] { FilterByProviderId.Value }, cancellationToken: cancellationToken);
                    ProviderFilterName = provider?.Name;
                }
            }

            _logger.LogInformation("Successfully fetched {AppCount} client applications.", Applications.Count);
        }
    }
}