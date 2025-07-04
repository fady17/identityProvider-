using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Orjnz.IdentityProvider.Web.Areas.Admin.Models;
using Orjnz.IdentityProvider.Web.Data;
using System;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Providers
{
    /// <summary>
    /// This Razor Page model handles displaying the detailed information of a single Provider entity.
    /// It provides a read-only view of the provider's configured properties.
    /// </summary>
    /// <remarks>
    /// Authorization for this page is handled by the convention in `Program.cs`.
    /// </remarks>
    public class DetailsModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<DetailsModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="DetailsModel"/> class.
        /// </summary>
        /// <param name="context">The application's database context for data access.</param>
        /// <param name="logger">The logger for recording page operations.</param>
        public DetailsModel(ApplicationDbContext context, ILogger<DetailsModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// The view model holding the provider's data to be displayed on the page.
        /// </summary>
        public ProviderViewModel Provider { get; set; } = new ProviderViewModel();

        /// <summary>
        /// Handles the GET request for the details page. It fetches the provider's data
        // from the database based on the provided ID and populates the view model.
        /// </summary>
        /// <param name="id">The GUID identifier of the provider to display.</param>
        public async Task<IActionResult> OnGetAsync(Guid? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var provider = await _context.Providers.FindAsync(id);

            if (provider == null)
            {
                return NotFound();
            }
            
            // Map the retrieved database entity to the view model for display.
            Provider = new ProviderViewModel
            {
                Id = provider.Id,
                Name = provider.Name,
                ShortCode = provider.ShortCode,
                WebsiteDomain = provider.WebsiteDomain,
                IsActive = provider.IsActive
            };

            return Page();
        }
    }
}