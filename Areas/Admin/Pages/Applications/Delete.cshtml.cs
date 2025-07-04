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
    /// <summary>
    /// This Razor Page model handles the deletion of a client application.
    /// It provides a confirmation step to prevent accidental deletion.
    /// </summary>
    /// <remarks>
    /// Authorization is handled by convention in `Program.cs`.
    /// </remarks>
    public class DeleteModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ApplicationDbContext _dbContext; // To fetch Provider display name
        private readonly ILogger<DeleteModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="DeleteModel"/> class.
        /// </summary>
        public DeleteModel(
            IOpenIddictApplicationManager applicationManager,
            ApplicationDbContext dbContext,
            ILogger<DeleteModel> logger)
        {
            _applicationManager = applicationManager;
            _dbContext = dbContext;
            _logger = logger;
        }

        /// <summary>
        /// A view model to hold the application data for display on the confirmation page.
        /// </summary>
        [BindProperty]
        public ApplicationDisplayViewModel ApplicationToDelete { get; set; } = new ApplicationDisplayViewModel();

        /// <summary>
        /// A property to hold any error messages to be displayed to the user.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// A view model specifically for displaying key details of the application to be deleted.
        /// </summary>
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

        /// <summary>
        /// Handles the GET request for the delete page. It fetches the application's details
        /// to display them to the user for confirmation.
        /// </summary>
        /// <param name="id">The unique identifier of the application to be deleted.</param>
        public async Task<IActionResult> OnGetAsync(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Delete Application GET: ID is null or empty.");
                return NotFound("Application ID not specified.");
            }

            var applicationObject = await _applicationManager.FindByIdAsync(id);
            // Ensure the application exists and is of our custom type to access custom properties.
            if (applicationObject == null || !(applicationObject is AppCustomOpenIddictApplication customApplication))
            {
                _logger.LogWarning("Delete Application GET: Application with ID {ApplicationId} not found or not of expected type.", id);
                return NotFound($"Application with ID '{id}' not found or is not of the correct type.");
            }

            // Populate the view model with data for the confirmation page.
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

            return Page();
        }

        /// <summary>
        /// Handles the POST request from the delete confirmation form.
        /// This action performs the actual deletion of the application.
        /// </summary>
        /// <param name="id">The unique identifier of the application to be deleted.</param>
        public async Task<IActionResult> OnPostAsync(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Delete Application POST: ID is null or empty.");
                return NotFound("Application ID not specified for deletion.");
            }

            var applicationToDeleteObject = await _applicationManager.FindByIdAsync(id);
            if (applicationToDeleteObject == null)
            {
                // This can happen if the application was deleted by another user/process
                // between the GET and POST requests.
                _logger.LogWarning("Delete Application POST: Application with ID {ApplicationId} not found. It might have been already deleted.", id);
                TempData["ErrorMessage"] = "Application not found or already deleted.";
                return RedirectToPage("./Index");
            }

            try
            {
                var clientId = await _applicationManager.GetClientIdAsync(applicationToDeleteObject);
                var displayName = await _applicationManager.GetDisplayNameAsync(applicationToDeleteObject);

                await _applicationManager.DeleteAsync(applicationToDeleteObject);
                _logger.LogInformation("Successfully deleted Application: {DisplayName} (ClientId: {ClientId}, ID: {ApplicationId})",
                    displayName, clientId, id);

                TempData["SuccessMessage"] = $"Application '{displayName}' ({clientId}) deleted successfully.";
                return RedirectToPage("./Index");
            }
            catch (Exception ex)
            {
                var clientIdForError = await _applicationManager.GetClientIdAsync(applicationToDeleteObject) ?? id;
                _logger.LogError(ex, "Error deleting application {ClientIdForError}.", clientIdForError);
                TempData["ErrorMessage"] = $"An error occurred while deleting application '{clientIdForError}'. Error: {ex.Message}";
                return RedirectToPage("./Index");
            }
        }
    }
}