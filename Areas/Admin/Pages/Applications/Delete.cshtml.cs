// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Applications/Delete.cshtml.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions; // For IOpenIddictApplicationManager and constants
using Orjnz.IdentityProvider.Web.Data; // For ApplicationDbContext (to get Provider name)
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
using System;
using System.Linq; // For FirstOrDefaultAsync if used with DbContext directly
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Applications
{
    // Authorization handled by convention
    public class DeleteModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ApplicationDbContext _dbContext; // To fetch Provider display name
        private readonly ILogger<DeleteModel> _logger;

        public DeleteModel(
            IOpenIddictApplicationManager applicationManager,
            ApplicationDbContext dbContext,
            ILogger<DeleteModel> logger)
        {
            _applicationManager = applicationManager;
            _dbContext = dbContext;
            _logger = logger;
        }

        [BindProperty] // Binds the application object for POST and its ID from route on GET
        public ApplicationDisplayViewModel ApplicationToDelete { get; set; } = new ApplicationDisplayViewModel();

        public string? ErrorMessage { get; set; }

        // ViewModel for display purposes on the Delete confirmation page
        public class ApplicationDisplayViewModel
        {
            public string? Id { get; set; }
            public string? ClientId { get; set; }
            public string? DisplayName { get; set; }
            public string? ClientType { get; set; }
            public string? ApplicationType { get; set; }
            public Guid? ProviderId { get; set; }
            public string? ProviderName { get; set; }
        }

        public async Task<IActionResult> OnGetAsync(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Delete Application GET: ID is null or empty.");
                return NotFound("Application ID not specified.");
            }

            var applicationObject = await _applicationManager.FindByIdAsync(id);
            if (applicationObject == null || !(applicationObject is AppCustomOpenIddictApplication customApplication))
            {
                _logger.LogWarning("Delete Application GET: Application with ID {ApplicationId} not found or not of expected type.", id);
                return NotFound($"Application with ID '{id}' not found or is not of the correct type.");
            }

            ApplicationToDelete.Id = await _applicationManager.GetIdAsync(customApplication);
            ApplicationToDelete.ClientId = await _applicationManager.GetClientIdAsync(customApplication);
            ApplicationToDelete.DisplayName = await _applicationManager.GetDisplayNameAsync(customApplication);
            ApplicationToDelete.ClientType = await _applicationManager.GetClientTypeAsync(customApplication);
            ApplicationToDelete.ApplicationType = await _applicationManager.GetApplicationTypeAsync(customApplication);
            ApplicationToDelete.ProviderId = customApplication.ProviderId;

            if (customApplication.ProviderId.HasValue)
            {
                var provider = await _dbContext.Providers.FindAsync(customApplication.ProviderId.Value);
                ApplicationToDelete.ProviderName = provider?.Name;
            }

            // Future: Could add checks here for active authorizations or tokens if strict pre-delete checks are needed,
            // though OpenIddict's cascading delete behavior or token validation usually handles orphaned entities.
            // For now, we rely on the user confirming the deletion of the application itself.

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string? id) // id from route
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Delete Application POST: ID is null or empty.");
                return NotFound("Application ID not specified for deletion.");
            }

            var applicationToDeleteObject = await _applicationManager.FindByIdAsync(id);
            if (applicationToDeleteObject == null)
            {
                _logger.LogWarning("Delete Application POST: Application with ID {ApplicationId} not found. It might have been already deleted.", id);
                TempData["ErrorMessage"] = "Application not found or already deleted.";
                return RedirectToPage("./Index");
            }

            // No need to cast to AppCustomOpenIddictApplication for DeleteAsync,
            // as the manager works with the object it found.

            try
            {
                var clientId = await _applicationManager.GetClientIdAsync(applicationToDeleteObject); // Get ClientId for logging before delete
                var displayName = await _applicationManager.GetDisplayNameAsync(applicationToDeleteObject);

                await _applicationManager.DeleteAsync(applicationToDeleteObject);
                _logger.LogInformation("Successfully deleted Application: {DisplayName} (ClientId: {ClientId}, ID: {ApplicationId})",
                    displayName, clientId, id);

                TempData["SuccessMessage"] = $"Application '{displayName}' ({clientId}) deleted successfully.";
                return RedirectToPage("./Index");
            }
            catch (Exception ex) // Catching general exception as concurrency or DB specific errors are less common for simple delete
            {
                var clientIdForError = await _applicationManager.GetClientIdAsync(applicationToDeleteObject) ?? id;
                _logger.LogError(ex, "Error deleting application {ClientIdForError}.", clientIdForError);
                // Repopulate data for display if returning to page with error
                // This requires re-fetching data as in OnGetAsync, or storing it in TempData/Session briefly.
                // For simplicity, redirecting to Index with a general error message is often sufficient for delete failures.
                TempData["ErrorMessage"] = $"An error occurred while deleting application '{clientIdForError}'. Error: {ex.Message}";
                return RedirectToPage("./Index"); // Or return Page() after repopulating ApplicationToDelete
            }
        }
    }
}