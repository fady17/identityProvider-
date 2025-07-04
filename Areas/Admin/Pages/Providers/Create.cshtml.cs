using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Orjnz.IdentityProvider.Web.Areas.Admin.Models;
using Orjnz.IdentityProvider.Web.Data;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Providers
{
    /// <summary>
    /// This Razor Page model handles the creation of new Provider entities. Providers represent
    /// tenants or organizations within the system. This page provides the form for an
    /// administrator to create a new provider record.
    /// </summary>
    /// <remarks>
    /// Authorization for this page is handled by the convention in `Program.cs`:
    /// `options.Conventions.AuthorizeAreaFolder("Admin", "/", "IDPAdminPolicy");`
    /// </remarks>
    public class CreateModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<CreateModel> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CreateModel"/> class.
        /// </summary>
        /// <param name="context">The application's database context for data access.</param>
        /// <param name="logger">The logger for recording page operations.</param>
        public CreateModel(ApplicationDbContext context, ILogger<CreateModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// The view model that binds to the create provider form.
        /// </summary>
        [BindProperty]
        public ProviderViewModel ProviderInput { get; set; } = new ProviderViewModel();

        /// <summary>
        /// Handles the GET request to display the create provider form.
        /// </summary>
        public IActionResult OnGet()
        {
            // Initialize the view model with default values.
            ProviderInput = new ProviderViewModel
            {
                IsActive = true
            };
            return Page();
        }

        /// <summary>
        /// Handles the POST request to create a new provider. This method validates the input,
        /// checks for uniqueness of the ShortCode, creates the entity, and saves it to the database.
        /// </summary>
        public async Task<IActionResult> OnPostAsync()
        {
            _logger.LogInformation("Create Provider POST request received");

            if (ProviderInput == null)
            {
                _logger.LogError("ProviderInput is null during POST");
                ModelState.AddModelError(string.Empty, "Form data is invalid. Please try again.");
                return Page();
            }

            // --- 1. Data Cleaning and Validation ---
            ProviderInput.Name = ProviderInput.Name?.Trim() ?? string.Empty;
            ProviderInput.ShortCode = ProviderInput.ShortCode?.Trim() ?? string.Empty;
            ProviderInput.WebsiteDomain = ProviderInput.WebsiteDomain?.Trim();

            // Perform manual validation checks in addition to data annotations.
            if (string.IsNullOrWhiteSpace(ProviderInput.Name))
            {
                ModelState.AddModelError(nameof(ProviderInput.Name), "Provider name is required.");
            }
            if (string.IsNullOrWhiteSpace(ProviderInput.ShortCode))
            {
                ModelState.AddModelError(nameof(ProviderInput.ShortCode), "Short code is required.");
            }

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Create Provider POST: Model state is invalid");
                // Log validation errors for debugging.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                var errors = ModelState.Where(x => x.Value.Errors.Count > 0)
                    .Select(x => new { Field = x.Key, Errors = x.Value.Errors.Select(e => e.ErrorMessage) });
#pragma warning restore CS8602 // Dereference of a possibly null reference.
                foreach (var error in errors)
                {
                    _logger.LogWarning("Validation error for {Field}: {Errors}", error.Field, string.Join(", ", error.Errors));
                }
                return Page();
            }

            // Normalize ShortCode to lowercase to ensure case-insensitive uniqueness.
            ProviderInput.ShortCode = ProviderInput.ShortCode.ToLowerInvariant();

            // Check for ShortCode uniqueness to prevent conflicts.
            bool shortCodeExists = await _context.Providers.AnyAsync(p => p.ShortCode == ProviderInput.ShortCode);
            if (shortCodeExists)
            {
                _logger.LogWarning("Create Provider POST: ShortCode '{ShortCode}' already exists", ProviderInput.ShortCode);
                ModelState.AddModelError(nameof(ProviderInput.ShortCode), "This Short Code is already in use. Please choose another.");
                return Page();
            }

            // --- 2. Map ViewModel to Entity ---
            var provider = new Provider
            {
                Id = Guid.NewGuid(),
                Name = ProviderInput.Name,
                ShortCode = ProviderInput.ShortCode,
                WebsiteDomain = string.IsNullOrWhiteSpace(ProviderInput.WebsiteDomain) ? null : ProviderInput.WebsiteDomain,
                IsActive = ProviderInput.IsActive,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            // --- 3. Persist to Database ---
            try
            {
                _context.Providers.Add(provider);
                await _context.SaveChangesAsync();
                
                _logger.LogInformation("Successfully created Provider: {ProviderName} (ID: {ProviderId}, ShortCode: {ProviderShortCode})",
                    provider.Name, provider.Id, provider.ShortCode);

                TempData["SuccessMessage"] = $"Provider '{provider.Name}' created successfully.";
                return RedirectToPage("./Index");
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Database error creating provider {ProviderName}", ProviderInput.Name);
                
                // Provide a more user-friendly error if a unique constraint was violated.
                if (ex.InnerException?.Message.Contains("UNIQUE constraint failed") == true ||
                    ex.InnerException?.Message.Contains("duplicate key") == true)
                {
                    ModelState.AddModelError(nameof(ProviderInput.ShortCode), "This Short Code is already in use. Please choose another.");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "An error occurred while creating the provider. Please try again.");
                }
                
                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error creating provider {ProviderName}", ProviderInput.Name);
                ModelState.AddModelError(string.Empty, "An unexpected error occurred. Please try again.");
                return Page();
            }
        }
    }
}