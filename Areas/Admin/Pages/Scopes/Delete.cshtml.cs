// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Scopes/Delete.cshtml.cs
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
    // Authorization handled by convention
    public class DeleteModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IOpenIddictApplicationManager _applicationManager; // To check if scope is in use by any app
        private readonly ILogger<DeleteModel> _logger;

        public DeleteModel(
            IOpenIddictScopeManager scopeManager,
            IOpenIddictApplicationManager applicationManager,
            ILogger<DeleteModel> logger)
        {
            _scopeManager = scopeManager;
            _applicationManager = applicationManager;
            _logger = logger;
        }

        [BindProperty]
        public ScopeDisplayViewModel ScopeToDelete { get; set; } = new ScopeDisplayViewModel();
        
        public string? ErrorMessage { get; set; }
        public bool CanDelete { get; set; } = true;
        public int LinkedApplicationCount { get; set; } = 0;

        // ViewModel for display on the confirmation page
        public class ScopeDisplayViewModel
        {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? DisplayName { get; set; }
        }

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

            ScopeToDelete.Id = await _scopeManager.GetIdAsync(customScope, cancellationToken);
            ScopeToDelete.Name = await _scopeManager.GetNameAsync(customScope, cancellationToken);
            ScopeToDelete.DisplayName = await _scopeManager.GetLocalizedDisplayNameAsync(customScope, cancellationToken);

            // Check if any application uses this scope in its permissions
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
                CanDelete = false;
                ErrorMessage = $"This scope ('{ScopeToDelete.Name}') cannot be deleted because it is currently granted as a permission to {LinkedApplicationCount} client application(s). Please remove this scope permission from these applications first.";
                _logger.LogWarning("Attempt to delete scope {ScopeName} (ID: {ScopeId}) which is used by {AppCount} applications.", ScopeToDelete.Name, ScopeToDelete.Id, LinkedApplicationCount);
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string? id, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(id))
            {
                _logger.LogWarning("Delete Scope POST: ID is null or empty from route.");
                return NotFound("Scope ID not specified for deletion.");
            }

            // ID for POST comes from asp-route-id in the form, or could use ScopeToDelete.Id if bound
            var scopeToDeleteObject = await _scopeManager.FindByIdAsync(id, cancellationToken);
            if (scopeToDeleteObject == null)
            {
                _logger.LogWarning("Delete Scope POST: Scope with ID {ScopeId} not found. It might have been already deleted.", id);
                TempData["ErrorMessage"] = "Scope not found or already deleted.";
                return RedirectToPage("./Index");
            }

            // Re-check dependencies before actual delete
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
                return RedirectToPage("./Index"); // Or back to this Delete page: return await OnGetAsync(id, cancellationToken);
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
                return RedirectToPage("./Index"); // Or return Page() after repopulating ScopeToDelete via OnGetAsync
            }
        }
    }
}