using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Orjnz.IdentityProvider.Web.Data; // For ApplicationDbContext and Provider entity
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;
using System;
using System.Linq; // For FirstOrDefaultAsync
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Providers
{
    /// <summary>
    /// This Razor Page model handles the deletion of a Provider entity.
    /// It includes a critical validation step to prevent the deletion of a provider
    /// that is currently linked to one or more client applications.
    /// </summary>
    /// <remarks>
    /// Authorization is handled by convention in `Program.cs`.
    /// </remarks>
    public class DeleteModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<DeleteModel> _logger;
        private readonly IOpenIddictApplicationManager _applicationManager;

        /// <summary>
        /// Initializes a new instance of the <see cref="DeleteModel"/> class.
        /// </summary>
        /// <param name="context">The application's database context.</param>
        /// <param name="applicationManager">The OpenIddict manager for application entities, used to check for links.</param>
        /// <param name="logger">The logger for recording page operations.</param>
        public DeleteModel(ApplicationDbContext context, 
                           IOpenIddictApplicationManager applicationManager,
                           ILogger<DeleteModel> logger)
        {
            _context = context;
            _applicationManager = applicationManager;
            _logger = logger;
        }

        /// <summary>
        /// The Provider entity to be deleted. It's bound from the route on GET and the form on POST.
        /// </summary>
        [BindProperty]
        public Provider? ProviderToDelete { get; set; }

        /// <summary>
        /// A property to hold any error messages to be displayed to the user.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// A flag indicating if the provider can be safely deleted. Defaults to true.
        /// Set to false if the provider is linked to any applications.
        /// </summary>
        public bool CanDelete { get; set; } = true;

        /// <summary>
        /// The number of client applications linked to this provider.
        /// </summary>
        public int LinkedApplicationCount { get; set; } = 0;

        /// <summary>
        /// Handles the GET request for the delete confirmation page. It fetches the provider
        /// and checks if it can be deleted by looking for linked applications.
        /// </summary>
        /// <param name="id">The GUID identifier of the provider.</param>
        public async Task<IActionResult> OnGetAsync(Guid? id)
        {
            if (id == null)
            {
                _logger.LogWarning("Delete Provider GET: ID is null.");
                return NotFound("Provider ID not specified.");
            }

            ProviderToDelete = await _context.Providers.FirstOrDefaultAsync(m => m.Id == id);

            if (ProviderToDelete == null)
            {
                _logger.LogWarning("Delete Provider GET: Provider with ID {ProviderId} not found.", id);
                return NotFound($"Provider with ID '{id}' not found.");
            }

            // Business Rule: Check if any OpenIddict Applications are linked to this Provider.
            // This is a critical check to maintain data integrity.
            long count = 0;
            await foreach (var appObject in _applicationManager.ListAsync(cancellationToken: HttpContext.RequestAborted))
            {
                if (appObject is AppCustomOpenIddictApplication customApp && customApp.ProviderId == ProviderToDelete.Id)
                {
                    count++;
                }
            }
            LinkedApplicationCount = (int)count;

            if (LinkedApplicationCount > 0)
            {
                CanDelete = false; // Prevent deletion.
                ErrorMessage = $"This provider ('{ProviderToDelete.Name}') cannot be deleted because it is linked to {LinkedApplicationCount} client application(s). Please reassign or delete these applications first.";
                _logger.LogWarning("Attempt to delete provider {ProviderId} which has {AppCount} linked applications.", ProviderToDelete.Id, LinkedApplicationCount);
            }

            return Page();
        }

        /// <summary>
        /// Handles the POST request to confirm and perform the deletion of the provider.
        /// </summary>
        /// <param name="id">The GUID identifier of the provider to be deleted.</param>
        public async Task<IActionResult> OnPostAsync(Guid? id)
        {
            if (id == null)
            {
                _logger.LogWarning("Delete Provider POST: ID is null.");
                return NotFound("Provider ID not specified for deletion.");
            }

            ProviderToDelete = await _context.Providers.FindAsync(id);

            if (ProviderToDelete == null)
            {
                _logger.LogWarning("Delete Provider POST: Provider with ID {ProviderId} not found during POST. It might have been already deleted.", id);
                TempData["ErrorMessage"] = "Provider not found or already deleted.";
                return RedirectToPage("./Index");
            }

            // Re-run the safety check in case the state changed between the GET and POST requests.
            long count = 0;
             await foreach (var appObject in _applicationManager.ListAsync(cancellationToken: HttpContext.RequestAborted))
            {
                if (appObject is AppCustomOpenIddictApplication customApp && customApp.ProviderId == ProviderToDelete.Id)
                {
                    count++;
                }
            }
            LinkedApplicationCount = (int)count;

            if (LinkedApplicationCount > 0)
            {
                _logger.LogWarning("Delete Provider POST: Deletion of provider {ProviderId} aborted as it now has {AppCount} linked applications.", ProviderToDelete.Id, LinkedApplicationCount);
                TempData["ErrorMessage"] = $"Deletion of '{ProviderToDelete.Name}' failed. It is linked to {LinkedApplicationCount} application(s).";
                return RedirectToPage("./Index");
            }

            try
            {
                _context.Providers.Remove(ProviderToDelete);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Successfully deleted Provider: {ProviderName} (ID: {ProviderId})",
                    ProviderToDelete.Name, ProviderToDelete.Id);

                TempData["SuccessMessage"] = $"Provider '{ProviderToDelete.Name}' deleted successfully.";
                return RedirectToPage("./Index");
            }
            catch (DbUpdateException ex)
            {
                // This catches other potential database-level integrity issues (e.g., foreign key constraints).
                _logger.LogError(ex, "Database error deleting provider {ProviderId} ({ProviderName}).", ProviderToDelete.Id, ProviderToDelete.Name);
                ErrorMessage = $"An error occurred while deleting the provider '{ProviderToDelete.Name}'. It might be in use by other parts of the system. Details: {ex.InnerException?.Message ?? ex.Message}";
                CanDelete = false;
                return Page(); // Re-display confirmation page with the error.
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error deleting provider {ProviderId} ({ProviderName}).", ProviderToDelete.Id, ProviderToDelete.Name);
                ErrorMessage = $"An unexpected error occurred while deleting '{ProviderToDelete.Name}'. Please try again.";
                CanDelete = false;
                return Page();
            }
        }
    }
}