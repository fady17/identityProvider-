using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Orjnz.IdentityProvider.Web.Data;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Providers
{
    public class IndexModel : PageModel
    {
        private readonly ApplicationDbContext _context;

        public IndexModel(ApplicationDbContext context)
        {
            _context = context;
        }

        public IList<Provider> Providers { get;set; } = new List<Provider>();

        public async Task OnGetAsync()
        {
            Providers = await _context.Providers.OrderBy(p => p.Name).ToListAsync();
        }
    }
}