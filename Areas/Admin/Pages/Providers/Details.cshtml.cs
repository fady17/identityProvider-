// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Providers/Details.cshtml.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Orjnz.IdentityProvider.Web.Areas.Admin.Models;
using Orjnz.IdentityProvider.Web.Data;
using System;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Providers
{
    public class DetailsModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<DetailsModel> _logger;

        public DetailsModel(ApplicationDbContext context, ILogger<DetailsModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        public ProviderViewModel Provider { get; set; } = new ProviderViewModel();

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