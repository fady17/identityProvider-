// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Providers/Edit.cshtml.cs
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
    // Authorization for this page is handled by the convention in Program.cs
    public class EditModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<EditModel> _logger;

        public EditModel(ApplicationDbContext context, ILogger<EditModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public ProviderViewModel ProviderInput { get; set; } = new ProviderViewModel();

        /// <summary>
        /// Handles the GET request to display the edit provider form.
        /// Loads the provider by ID and populates the ViewModel.
        /// </summary>
        /// <param name="id">The ID of the provider to edit.</param>
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

            // Map Entity to ViewModel
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
        /// Handles the POST request to update an existing provider.
        /// Validates input, checks for ShortCode uniqueness (if changed),
        /// updates the entity, and saves changes.
        /// </summary>
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Edit Provider POST: Model state is invalid for Provider ID {ProviderId}.", ProviderInput.Id);
                return Page(); // Re-display form with validation errors
            }

            var providerToUpdate = await _context.Providers.FindAsync(ProviderInput.Id);

            if (providerToUpdate == null)
            {
                _logger.LogWarning("Edit Provider POST: Provider with ID {ProviderId} not found during POST. Possible concurrency issue or invalid ID.", ProviderInput.Id);
                return NotFound($"Provider with ID '{ProviderInput.Id}' not found.");
            }

            // Normalize ShortCode if desired
            // ProviderInput.ShortCode = ProviderInput.ShortCode.ToLowerInvariant();

            // Check for ShortCode uniqueness if it has been changed
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

            // Map updated ViewModel properties back to the entity
            providerToUpdate.Name = ProviderInput.Name;
            providerToUpdate.ShortCode = ProviderInput.ShortCode;
            providerToUpdate.WebsiteDomain = ProviderInput.WebsiteDomain;
            providerToUpdate.IsActive = ProviderInput.IsActive;
            providerToUpdate.UpdatedAt = DateTime.UtcNow; // Update the timestamp

            _context.Attach(providerToUpdate).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Successfully updated Provider: {ProviderName} (ID: {ProviderId})",
                    providerToUpdate.Name, providerToUpdate.Id);

                TempData["SuccessMessage"] = $"Provider '{providerToUpdate.Name}' updated successfully.";
                return RedirectToPage("./Index"); // Redirect to the list of providers
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogError(ex, "Concurrency error updating provider {ProviderId}.", ProviderInput.Id);
                // Check if the entity was deleted by another user
                if (!await ProviderExistsAsync(ProviderInput.Id))
                {
                    return NotFound($"Provider with ID '{ProviderInput.Id}' was deleted by another user.");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "The record you attempted to edit "
                        + "was modified by another user after you got the original value. "
                        + "Your edit operation was canceled. Please try again.");
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

        private async Task<bool> ProviderExistsAsync(Guid id)
        {
            return await _context.Providers.AnyAsync(e => e.Id == id);
        }
    }
}