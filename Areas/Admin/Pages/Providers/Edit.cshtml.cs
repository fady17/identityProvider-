using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Orjnz.IdentityProvider.Web.Areas.Admin.Models; // For ProviderViewModel
using Orjnz.IdentityProvider.Web.Data; // For ApplicationDbContext and Provider entity
using System;
using System.Linq; // For FirstOrDefaultAsync
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Providers
{
    /// <summary>
    /// This Razor Page model handles the editing of an existing Provider entity.
    /// It populates a form with the provider's current data and processes the
    /// submission to apply updates to the database.
    /// </summary>
    /// <remarks>
    /// Authorization for this page is handled by the convention in `Program.cs`.
    /// </remarks>
    public class EditModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<EditModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="EditModel"/> class.
        /// </summary>
        public EditModel(ApplicationDbContext context, ILogger<EditModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// The view model that binds to the edit provider form.
        /// </summary>
        [BindProperty]
        public ProviderViewModel ProviderInput { get; set; } = new ProviderViewModel();

        /// <summary>
        /// Handles the GET request to display the edit provider form.
        /// This method loads the provider by its ID and populates the view model.
        /// </summary>
        /// <param name="id">The GUID identifier of the provider to edit.</param>
        public async Task<IActionResult> OnGetAsync(Guid? id)
        {
            if (id == null)
            {
                _logger.LogWarning("Edit Provider GET: ID is null.");
                return NotFound("Provider ID not specified.");
            }

            var provider = await _context.Providers.FindAsync(id);

            if (provider == null)
            {
                _logger.LogWarning("Edit Provider GET: Provider with ID {ProviderId} not found.", id);
                return NotFound($"Provider with ID '{id}' not found.");
            }

            // Map the retrieved database entity to the view model for display in the form.
            ProviderInput = new ProviderViewModel
            {
                Id = provider.Id,
                Name = provider.Name,
                ShortCode = provider.ShortCode,
                WebsiteDomain = provider.WebsiteDomain,
                IsActive = provider.IsActive
            };

            return Page();
        }

        /// <summary>
        /// Handles the POST request to update an existing provider in the database.
        /// This method validates the submitted data, checks for uniqueness constraints (if applicable),
        /// updates the entity properties, and saves the changes.
        /// </summary>
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Edit Provider POST: Model state is invalid for Provider ID {ProviderId}.", ProviderInput.Id);
                return Page(); // Re-display the form with validation errors.
            }

            var providerToUpdate = await _context.Providers.FindAsync(ProviderInput.Id);

            if (providerToUpdate == null)
            {
                _logger.LogWarning("Edit Provider POST: Provider with ID {ProviderId} not found during POST. Possible concurrency issue or invalid ID.", ProviderInput.Id);
                return NotFound($"Provider with ID '{ProviderInput.Id}' not found.");
            }

            // If the ShortCode has been changed, we must ensure the new one is not already in use by another provider.
            if (providerToUpdate.ShortCode != ProviderInput.ShortCode)
            {
                bool shortCodeExistsForAnotherProvider = await _context.Providers
                    .AnyAsync(p => p.ShortCode == ProviderInput.ShortCode && p.Id != ProviderInput.Id);
                if (shortCodeExistsForAnotherProvider)
                {
                    _logger.LogWarning("Edit Provider POST: New ShortCode '{ShortCode}' for Provider ID {ProviderId} already exists for another provider.",
                        ProviderInput.ShortCode, ProviderInput.Id);
                    ModelState.AddModelError(nameof(ProviderViewModel.ShortCode), "This Short Code is already in use by another provider. Please choose a different one.");
                    return Page();
                }
            }

            // Map the updated view model properties back to the tracked database entity.
            providerToUpdate.Name = ProviderInput.Name;
            providerToUpdate.ShortCode = ProviderInput.ShortCode;
            providerToUpdate.WebsiteDomain = ProviderInput.WebsiteDomain;
            providerToUpdate.IsActive = ProviderInput.IsActive;
            providerToUpdate.UpdatedAt = DateTime.UtcNow; // Update the modification timestamp.

            // Explicitly set the entity's state to Modified.
            _context.Attach(providerToUpdate).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Successfully updated Provider: {ProviderName} (ID: {ProviderId})",
                    providerToUpdate.Name, providerToUpdate.Id);

                TempData["SuccessMessage"] = $"Provider '{providerToUpdate.Name}' updated successfully.";
                return RedirectToPage("./Index");
            }
            catch (DbUpdateConcurrencyException ex)
            {
                // This exception occurs if another user modified the same record after it was loaded.
                _logger.LogError(ex, "Concurrency error updating provider {ProviderId}.", ProviderInput.Id);
                if (!await ProviderExistsAsync(ProviderInput.Id))
                {
                    return NotFound($"Provider with ID '{ProviderInput.Id}' was deleted by another user.");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "The record you attempted to edit was modified by another user. Your edit was canceled. Please try again.");
                }
                return Page();
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Database error updating provider {ProviderId}.", ProviderInput.Id);
                ModelState.AddModelError(string.Empty, "An error occurred while updating the provider. Please try again.");
                if (ex.InnerException != null) { ModelState.AddModelError(string.Empty, $"Database error: {ex.InnerException.Message}"); }
                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error updating provider {ProviderId}.", ProviderInput.Id);
                ModelState.AddModelError(string.Empty, "An unexpected error occurred. Please try again.");
                return Page();
            }
        }

        /// <summary>
        /// A helper method to check if a provider with the given ID exists in the database.
        /// </summary>
        /// <param name="id">The GUID identifier of the provider.</param>
        private async Task<bool> ProviderExistsAsync(Guid id)
        {
            return await _context.Providers.AnyAsync(e => e.Id == id);
        }
    }
}