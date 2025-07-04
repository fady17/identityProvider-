using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Orjnz.IdentityProvider.Web.Data;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Providers
{
    /// <summary>
    /// This Razor Page model handles the listing of all Provider entities.
    /// It fetches all providers from the database and displays them in a list.
    /// </summary>
    /// <remarks>
    /// Authorization for this page is handled by the convention in `Program.cs`.
    /// </remarks>
    public class IndexModel : PageModel
    {
        private readonly ApplicationDbContext _context;

        /// <summary>
        /// Initializes a new instance of the <see cref="IndexModel"/> class.
        /// </summary>
        /// <param name="context">The application's database context for data access.</param>
        public IndexModel(ApplicationDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// A list of all <see cref="Provider"/> entities to be displayed on the page.
        /// </summary>
        public IList<Provider> Providers { get;set; } = new List<Provider>();

        /// <summary>
        /// Handles the GET request for the index page. It retrieves all providers
        /// from the database, orders them by name, and populates the `Providers` property.
        /// </summary>
        public async Task OnGetAsync()
        {
            // Retrieve all providers from the database and order them alphabetically by name for display.
            Providers = await _context.Providers.OrderBy(p => p.Name).ToListAsync();
        }
    }
}