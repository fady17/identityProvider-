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
    /// <summary>
    /// This Razor Page model handles the listing of all registered client applications.
    /// It provides a summary view and allows for filtering applications by the associated provider.
    /// </summary>
    /// <remarks>
    /// Authorization is handled by convention in `Program.cs`.
    /// </remarks>
    public class IndexModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ApplicationDbContext _dbContext; // To fetch Provider name for filter display
        private readonly ILogger<IndexModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="IndexModel"/> class.
        /// </summary>
        public IndexModel(
            IOpenIddictApplicationManager applicationManager,
            ApplicationDbContext dbContext,
            ILogger<IndexModel> logger)
        {
            _applicationManager = applicationManager;
            _dbContext = dbContext;
            _logger = logger;
        }

        /// <summary>
        /// A list of application summaries to be displayed in the main table.
        /// </summary>
        public IList<ApplicationSummaryViewModel> Applications { get; set; } = new List<ApplicationSummaryViewModel>();

        /// <summary>
        /// Binds to the `filterByProviderId` query string parameter to allow filtering the application list.
        /// </summary>
        [BindProperty(SupportsGet = true)]
        public Guid? FilterByProviderId { get; set; }

        /// <summary>
        /// The name of the provider being used as a filter, for display purposes on the page.
        /// </summary>
        public string? ProviderFilterName { get; set; }

        /// <summary>
        /// A view model representing a summary of an application for the index list.
        /// </summary>
        public class ApplicationSummaryViewModel
        {
            public string? Id { get; set; }
            public string? ClientId { get; set; }
            public string? DisplayName { get; set; }
            public string? ClientType { get; set; }
            public string? ApplicationType { get; set; }
            public Guid? ProviderId { get; set; }
            public string? ProviderName { get; set; }
            public int RedirectUriCount { get; set; }
            public int PostLogoutRedirectUriCount { get; set; }
        }

        /// <summary>
        /// Handles the GET request for the index page. It fetches the list of applications,
        /// applies any filters, and populates the `Applications` property.
        /// </summary>
        public async Task OnGetAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Fetching list of client applications. FilterByProviderId: {FilterProviderId}", FilterByProviderId);

            var applicationsList = new List<ApplicationSummaryViewModel>();
            
            // Collect all applications into a temporary list. This avoids issues with multiple
            // async operations within a single `await foreach` loop.
            var allApplications = new List<AppCustomOpenIddictApplication>();
            await foreach (var appObject in _applicationManager.ListAsync(count: 1000, offset: 0, cancellationToken: cancellationToken).WithCancellation(cancellationToken))
            {
                if (appObject is AppCustomOpenIddictApplication customApp)
                {
                    // If a provider filter is active, only include applications that match the provider ID.
                    if (FilterByProviderId.HasValue && customApp.ProviderId != FilterByProviderId.Value)
                    {
                        continue;
                    }
                    allApplications.Add(customApp);
                }
                else if (appObject != null)
                {
                    _logger.LogWarning("Found application of unexpected type: {Type}", appObject.GetType().FullName);
                }
            }

            // To avoid N+1 database queries, batch load all necessary provider names in a single query.
            var providerIds = allApplications.Where(app => app.ProviderId.HasValue).Select(app => app.ProviderId!.Value).Distinct().ToList();
            var providerNames = new Dictionary<Guid, string>();
            if (providerIds.Any())
            {
                providerNames = await _dbContext.Providers
                    .Where(p => providerIds.Contains(p.Id))
                    .ToDictionaryAsync(p => p.Id, p => p.Name, cancellationToken);
            }

            // Now, build the final view model list from the in-memory data.
            foreach (var customApp in allApplications)
            {
                providerNames.TryGetValue(customApp.ProviderId ?? Guid.Empty, out var providerName);

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

            // If a filter is active, get the provider's name to display it as a page heading.
            if (FilterByProviderId.HasValue)
            {
                providerNames.TryGetValue(FilterByProviderId.Value, out var filterProviderName);
                if(string.IsNullOrEmpty(ProviderFilterName))
                {
                     var provider = await _dbContext.Providers.FindAsync(new object[] { FilterByProviderId.Value }, cancellationToken: cancellationToken);
                     ProviderFilterName = provider?.Name;
                }
            }

            _logger.LogInformation("Successfully fetched {AppCount} client applications.", Applications.Count);
        }
    }
}