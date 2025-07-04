using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions; // For IOpenIddictScopeManager
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictScope
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Scopes
{
    /// <summary>
    /// This Razor Page model handles the deletion of an OpenIddict scope.
    /// It provides a confirmation step and includes a crucial validation to prevent the deletion
    /// of a scope that is actively being used as a permission by one or more client applications.
    /// </summary>
    /// <remarks>
    /// Authorization is handled by convention in `Program.cs`.
    /// </remarks>
    public class DeleteModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ILogger<DeleteModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="DeleteModel"/> class.
        /// </summary>
        /// <param name="scopeManager">The OpenIddict manager for scope entities.</param>
        /// <param name="applicationManager">The OpenIddict manager for application entities, used to check for dependencies.</param>
        /// <param name="logger">The logger for recording page operations.</param>
        public DeleteModel(
            IOpenIddictScopeManager scopeManager,
            IOpenIddictApplicationManager applicationManager,
            ILogger<DeleteModel> logger)
        {
            _scopeManager = scopeManager;
            _applicationManager = applicationManager;
            _logger = logger;
        }

        /// <summary>
        /// A view model to hold the scope data for display on the confirmation page.
        /// </summary>
        [BindProperty]
        public ScopeDisplayViewModel ScopeToDelete { get; set; } = new ScopeDisplayViewModel();
        
        /// <summary>
        /// A property to hold any error messages to be displayed to the user.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// A flag indicating if the scope can be safely deleted. Defaults to true.
        /// Set to false if the scope is in use by any applications.
        /// </summary>
        public bool CanDelete { get; set; } = true;

        /// <summary>
        /// The number of client applications that have been granted permission to use this scope.
        /// </summary>
        public int LinkedApplicationCount { get; set; } = 0;

        /// <summary>
        /// A view model specifically for displaying key details of the scope to be deleted.
        /// </summary>
        public class ScopeDisplayViewModel
        {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? DisplayName { get; set; }
        }

        /// <summary>
        /// Handles the GET request for the delete confirmation page. It fetches the scope
        /// and checks if it can be deleted by looking for dependencies in client applications.
        /// </summary>
        /// <param name="id">The unique identifier of the scope to be deleted.</param>
        /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
        public async Task<IActionResult> OnGetAsync(string? id, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Delete Scope GET: ID is null or empty.");
                return NotFound("Scope ID not specified.");
            }

            var scopeObject = await _scopeManager.FindByIdAsync(id, cancellationToken);
            if (scopeObject == null || !(scopeObject is AppCustomOpenIddictScope customScope))
            {
                _logger.LogWarning("Delete Scope GET: Scope with ID {ScopeId} not found or not of expected type.", id);
                return NotFound($"Scope with ID '{id}' not found or is not of the correct type.");
            }
            
            // Populate the view model with data for the confirmation page.
            ScopeToDelete.Id = await _scopeManager.GetIdAsync(customScope, cancellationToken);
            ScopeToDelete.Name = await _scopeManager.GetNameAsync(customScope, cancellationToken);
            ScopeToDelete.DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(customScope, cancellationToken);

            // Business Rule: Check if any application has been granted permission for this scope.
            string permissionToCheck = OpenIddictConstants.Permissions.Prefixes.Scope + ScopeToDelete.Name;
            long appCount = 0;
            await foreach (var appObject in _applicationManager.ListAsync(cancellationToken: cancellationToken).WithCancellation(cancellationToken))
            {
                var permissions = await _applicationManager.GetPermissionsAsync(appObject, cancellationToken);
                if (permissions.Contains(permissionToCheck))
                {
                    appCount++;
                }
            }
            LinkedApplicationCount = (int)appCount;

            if (LinkedApplicationCount > 0)
            {
                CanDelete = false; // Prevent deletion.
                ErrorMessage = $"This scope ('{ScopeToDelete.Name}') cannot be deleted because it is currently granted as a permission to {LinkedApplicationCount} client application(s). Please remove this scope permission from these applications first.";
                _logger.LogWarning("Attempt to delete scope {ScopeName} (ID: {ScopeId}) which is used by {AppCount} applications.", ScopeToDelete.Name, ScopeToDelete.Id, LinkedApplicationCount);
            }

            return Page();
        }

        /// <summary>
        /// Handles the POST request to confirm and perform the deletion of the scope.
        /// </summary>
        /// <param name="id">The unique identifier of the scope to be deleted.</param>
        /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
        public async Task<IActionResult> OnPostAsync(string? id, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Delete Scope POST: ID is null or empty from route.");
                return NotFound("Scope ID not specified for deletion.");
            }

            var scopeToDeleteObject = await _scopeManager.FindByIdAsync(id, cancellationToken);
            if (scopeToDeleteObject == null)
            {
                _logger.LogWarning("Delete Scope POST: Scope with ID {ScopeId} not found. It might have been already deleted.", id);
                TempData["ErrorMessage"] = "Scope not found or already deleted.";
                return RedirectToPage("./Index");
            }

            // Re-run the dependency check to handle race conditions where a link might have been added
            // between the GET and POST requests.
            string scopeNameForCheck = await _scopeManager.GetNameAsync(scopeToDeleteObject, cancellationToken) ?? string.Empty;
            string permissionToCheck = OpenIddictConstants.Permissions.Prefixes.Scope + scopeNameForCheck;
            long appCount = 0;
            await foreach (var appObject in _applicationManager.ListAsync(cancellationToken: cancellationToken).WithCancellation(cancellationToken))
            {
                var permissions = await _applicationManager.GetPermissionsAsync(appObject, cancellationToken);
                if (permissions.Contains(permissionToCheck))
                {
                    appCount++;
                }
            }

            if (appCount > 0)
            {
                 _logger.LogWarning("Delete Scope POST: Deletion of scope {ScopeName} aborted as it is now used by {AppCount} applications.", scopeNameForCheck, appCount);
                TempData["ErrorMessage"] = $"Deletion of scope '{scopeNameForCheck}' failed. It is in use by {appCount} application(s).";
                return RedirectToPage("./Index");
            }

            try
            {
                await _scopeManager.DeleteAsync(scopeToDeleteObject, cancellationToken);
                _logger.LogInformation("Successfully deleted Scope: {ScopeName} (ID: {ScopeId})", scopeNameForCheck, id);

                TempData["SuccessMessage"] = $"Scope '{scopeNameForCheck}' deleted successfully.";
                return RedirectToPage("./Index");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting scope {ScopeName} (ID: {ScopeId}).", scopeNameForCheck, id);
                TempData["ErrorMessage"] = $"An error occurred while deleting scope '{scopeNameForCheck}'. Error: {ex.Message}";
                return RedirectToPage("./Index");
            }
        }
    }
}