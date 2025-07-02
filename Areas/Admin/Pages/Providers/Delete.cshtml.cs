// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Providers/Delete.cshtml.cs
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
    // Authorization handled by convention in Program.cs
    public class DeleteModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<DeleteModel> _logger;
        private readonly IOpenIddictApplicationManager _applicationManager; // To check for linked applications


        public DeleteModel(ApplicationDbContext context, 
                           IOpenIddictApplicationManager applicationManager, // Inject application manager
                           ILogger<DeleteModel> logger)
        {
            _context = context;
            _applicationManager = applicationManager;
            _logger = logger;
        }

        [BindProperty] // Binds the Provider from POST and its ID from route on GET
        public Provider? ProviderToDelete { get; set; }

        public string? ErrorMessage { get; set; }
        public bool CanDelete { get; set; } = true; // Assume can delete by default
        public int LinkedApplicationCount { get; set; } = 0;


        /// <summary>
        /// Handles GET request. Fetches the provider and checks if it can be deleted.
        /// </summary>
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

            // Check if there are any OpenIddict Applications linked to this Provider
            // We need to iterate through applications because AppCustomOpenIddictApplication.ProviderId is nullable
            // and the link is from Application -> Provider.
            // This might be slow if there are many applications. Consider a more optimized query if performance is an issue.
            long count = 0;
            await foreach (var appObject in _applicationManager.ListAsync(cancellationToken: HttpContext.RequestAborted))
            {
                if (appObject is AppCustomOpenIddictApplication customApp && customApp.ProviderId == ProviderToDelete.Id)
                {
                    count++;
                }
            }
            LinkedApplicationCount = (int)count; // Assuming count won't exceed int.MaxValue for display

            if (LinkedApplicationCount > 0)
            {
                CanDelete = false;
                ErrorMessage = $"This provider ('{ProviderToDelete.Name}') cannot be deleted because it is linked to {LinkedApplicationCount} client application(s). Please reassign or delete these applications first.";
                _logger.LogWarning("Attempt to delete provider {ProviderId} which has {AppCount} linked applications.", ProviderToDelete.Id, LinkedApplicationCount);
            }

            return Page();
        }

        /// <summary>
        /// Handles POST request to confirm and perform deletion.
        /// </summary>
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
                TempData["ErrorMessage"] = "Provider not found or already deleted."; // Use TempData for messages on redirect
                return RedirectToPage("./Index");
            }

            // Re-check if deletion is allowed (e.g., if linked applications were added between GET and POST)
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
                return RedirectToPage("./Index"); // Or back to this Delete page with error: return await OnGetAsync(id);
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
            catch (DbUpdateException ex) // Catches issues like FK constraints if any other entities depend on Provider
            {
                _logger.LogError(ex, "Database error deleting provider {ProviderId} ({ProviderName}).", ProviderToDelete.Id, ProviderToDelete.Name);
                // Check for specific FK constraint errors if needed
                ErrorMessage = $"An error occurred while deleting the provider '{ProviderToDelete.Name}'. It might be in use by other parts of the system. Details: {ex.InnerException?.Message ?? ex.Message}";
                CanDelete = false; // Re-set based on error
                return Page(); // Re-display confirmation page with error
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