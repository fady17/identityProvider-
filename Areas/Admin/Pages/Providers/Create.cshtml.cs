// File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Providers/Create.cshtml.cs
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
    // Authorization for this page is handled by the convention in Program.cs:
    // options.Conventions.AuthorizeAreaFolder("Admin", "/", "IDPAdminPolicy");
    public class CreateModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<CreateModel> _logger;

        public CreateModel(ApplicationDbContext context, ILogger<CreateModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public ProviderViewModel ProviderInput { get; set; } = new ProviderViewModel();

        /// <summary>
        /// Handles the GET request to display the create provider form.
        /// </summary>
        public IActionResult OnGet()
        {
            // Initialize with defaults - ensure IsActive is true by default
            ProviderInput = new ProviderViewModel
            {
                IsActive = true
            };
            return Page();
        }

        /// <summary>
        /// Handles the POST request to create a new provider.
        /// Validates the input, checks for ShortCode uniqueness, creates the entity,
        /// and saves it to the database.
        /// </summary>
        public async Task<IActionResult> OnPostAsync()
        {
            _logger.LogInformation("Create Provider POST request received");
             _logger.LogInformation("ProviderInput is null: {IsNull}", ProviderInput == null);
    if (ProviderInput != null)
    {
        _logger.LogInformation("Name: '{Name}', ShortCode: '{ShortCode}'", 
            ProviderInput.Name ?? "NULL", 
            ProviderInput.ShortCode ?? "NULL");
    }

            // Ensure ProviderInput is not null
            if (ProviderInput == null)
            {
                _logger.LogError("ProviderInput is null during POST");
                ModelState.AddModelError(string.Empty, "Form data is invalid. Please try again.");
                return Page();
            }

            // Trim whitespace from string properties to avoid empty string issues
            ProviderInput.Name = ProviderInput.Name?.Trim() ?? string.Empty;
            ProviderInput.ShortCode = ProviderInput.ShortCode?.Trim() ?? string.Empty;
            ProviderInput.WebsiteDomain = ProviderInput.WebsiteDomain?.Trim();

            // Additional validation beyond data annotations
            if (string.IsNullOrWhiteSpace(ProviderInput.Name))
            {
                ModelState.AddModelError(nameof(ProviderInput.Name), "Provider name is required.");
            }

            if (string.IsNullOrWhiteSpace(ProviderInput.ShortCode))
            {
                ModelState.AddModelError(nameof(ProviderInput.ShortCode), "Short code is required.");
            }

            // Validate ModelState
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Create Provider POST: Model state is invalid");

                // Log validation errors for debugging
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                var errors = ModelState
                    .Where(x => x.Value.Errors.Count > 0)
                    .Select(x => new { Field = x.Key, Errors = x.Value.Errors.Select(e => e.ErrorMessage) });
#pragma warning restore CS8602 // Dereference of a possibly null reference.

                foreach (var error in errors)
                {
                    _logger.LogWarning("Validation error for {Field}: {Errors}", 
                        error.Field, string.Join(", ", error.Errors));
                }

                return Page();
            }

            // Normalize ShortCode to lowercase for consistency
            ProviderInput.ShortCode = ProviderInput.ShortCode.ToLowerInvariant();

            // Check for ShortCode uniqueness
            bool shortCodeExists = await _context.Providers
                                        .AnyAsync(p => p.ShortCode == ProviderInput.ShortCode);
            if (shortCodeExists)
            {
                _logger.LogWarning("Create Provider POST: ShortCode '{ShortCode}' already exists", ProviderInput.ShortCode);
                ModelState.AddModelError(nameof(ProviderInput.ShortCode), 
                    "This Short Code is already in use. Please choose another.");
                return Page();
            }

            // Map ViewModel to Entity
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
                
                // Check for specific constraint violations
                if (ex.InnerException?.Message.Contains("UNIQUE constraint failed") == true ||
                    ex.InnerException?.Message.Contains("duplicate key") == true)
                {
                    ModelState.AddModelError(nameof(ProviderInput.ShortCode), 
                        "This Short Code is already in use. Please choose another.");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, 
                        "An error occurred while creating the provider. Please try again.");
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
// // File: Orjnz.IdentityProvider.Web/Areas/Admin/Pages/Providers/Create.cshtml.cs
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.AspNetCore.Mvc.RazorPages;
// using Microsoft.EntityFrameworkCore; // For ToListAsync, AnyAsync
// using Microsoft.Extensions.Logging;
// using Orjnz.IdentityProvider.Web.Areas.Admin.Models; // For ProviderViewModel
// using Orjnz.IdentityProvider.Web.Data; // For ApplicationDbContext and Provider entity
// using System;
// using System.Threading.Tasks;

// namespace Orjnz.IdentityProvider.Web.Areas.Admin.Pages.Providers
// {
//     // Authorization for this page is handled by the convention in Program.cs:
//     // options.Conventions.AuthorizeAreaFolder("Admin", "/", "IDPAdminPolicy");
//     public class CreateModel : PageModel
//     {
//         private readonly ApplicationDbContext _context;
//         private readonly ILogger<CreateModel> _logger;

//         public CreateModel(ApplicationDbContext context, ILogger<CreateModel> logger)
//         {
//             _context = context;
//             _logger = logger;
//         }

//         [BindProperty]
//         public ProviderViewModel ProviderInput { get; set; } = new ProviderViewModel();

//         /// <summary>
//         /// Handles the GET request to display the create provider form.
//         /// Initializes the ViewModel with default values if necessary.
//         /// </summary>
//         public IActionResult OnGet()
//         {
//             // Initialize with defaults if needed, e.g.:
//             // ProviderInput.IsActive = true; 
//             // (already defaulted in ProviderViewModel and Provider entity)
//             return Page();
//         }
//         // Enhanced OnPostAsync method with comprehensive debugging
// public async Task<IActionResult> OnPostAsync()
// {
//     _logger.LogInformation("====== CREATE OnPostAsync - Handler Invoked ======");
    
//     // Log the raw form data
//     _logger.LogInformation("Form Data Count: {Count}", HttpContext.Request.Form.Count);
//     foreach (var formField in HttpContext.Request.Form)
//     {
//         _logger.LogInformation("Form Field: {Key} = {Value}", formField.Key, formField.Value);
//     }
    
//     // Log the bound model properties
//     _logger.LogInformation("ProviderInput is null: {IsNull}", ProviderInput == null);
//     if (ProviderInput != null)
//     {
//         _logger.LogInformation("ProviderInput.Name: '{Name}'", ProviderInput.Name ?? "NULL");
//         _logger.LogInformation("ProviderInput.ShortCode: '{ShortCode}'", ProviderInput.ShortCode ?? "NULL");
//         _logger.LogInformation("ProviderInput.WebsiteDomain: '{WebsiteDomain}'", ProviderInput.WebsiteDomain ?? "NULL");
//         _logger.LogInformation("ProviderInput.IsActive: {IsActive}", ProviderInput.IsActive);
//     }
    
//     // Check ModelState validity and log all errors
//     _logger.LogInformation("ModelState.IsValid: {IsValid}", ModelState.IsValid);
//     _logger.LogInformation("ModelState.ErrorCount: {ErrorCount}", ModelState.ErrorCount);
    
//     foreach (var entry in ModelState)
//     {
//         _logger.LogInformation("ModelState Key: {Key}, AttemptedValue: '{AttemptedValue}', HasErrors: {HasErrors}", 
//             entry.Key, 
//             entry.Value.AttemptedValue ?? "NULL",
//             entry.Value.Errors.Any());
            
//         if (entry.Value.Errors.Any())
//         {
//             foreach (var error in entry.Value.Errors)
//             {
//                 _logger.LogWarning("ModelState Error for {Key}: {ErrorMessage} (Exception: {Exception})", 
//                     entry.Key, 
//                     error.ErrorMessage,
//                     error.Exception?.Message ?? "None");
//             }
//         }
//     }

//     if (!ModelState.IsValid)
//     {
//         _logger.LogWarning("Create Provider POST: Model state is invalid. Returning to form.");
        
//         // Add a general error message to help identify the issue
//         if (!ModelState.ContainsKey(string.Empty))
//         {
//             ModelState.AddModelError(string.Empty, "Form validation failed. Please check all required fields.");
//         }
        
//         return Page();
//     }

//     // Rest of your existing code...
    
//     // Check for ShortCode uniqueness
//     bool shortCodeExists = await _context.Providers
//                                 .AnyAsync(p => p.ShortCode == ProviderInput.ShortCode);
//     if (shortCodeExists)
//     {
//         _logger.LogWarning("Create Provider POST: ShortCode '{ShortCode}' already exists.", ProviderInput.ShortCode);
//         ModelState.AddModelError(nameof(ProviderViewModel.ShortCode), "This Short Code is already in use. Please choose another.");
//         return Page();
//     }

//             // Map ViewModel to Entity
// #pragma warning disable CS8601 // Possible null reference assignment.
// #pragma warning disable CS8602 // Dereference of a possibly null reference.
//             var provider = new Provider
//     {
//         Id = Guid.NewGuid(),
//         Name = ProviderInput.Name,
//         ShortCode = ProviderInput.ShortCode,
//         WebsiteDomain = ProviderInput.WebsiteDomain,
//         IsActive = ProviderInput.IsActive,
//         CreatedAt = DateTime.UtcNow,
//         UpdatedAt = DateTime.UtcNow
//     };
// #pragma warning restore CS8602 // Dereference of a possibly null reference.
// #pragma warning restore CS8601 // Possible null reference assignment.

//             try
//     {
//         _context.Providers.Add(provider);
//         await _context.SaveChangesAsync();
//         _logger.LogInformation("Successfully created Provider: {ProviderName} (ID: {ProviderId}, ShortCode: {ProviderShortCode})",
//             provider.Name, provider.Id, provider.ShortCode);

//         TempData["SuccessMessage"] = $"Provider '{provider.Name}' created successfully.";
//         return RedirectToPage("./Index");
//     }
//     catch (DbUpdateException ex)
//     {
//         _logger.LogError(ex, "Error creating provider {ProviderName} in database.", ProviderInput.Name);
//         ModelState.AddModelError(string.Empty, "An error occurred while creating the provider. Please try again.");
//         if (ex.InnerException != null)
//         {
//             _logger.LogError("Inner exception: {InnerExceptionMessage}", ex.InnerException.Message);
//             ModelState.AddModelError(string.Empty, $"Database error: {ex.InnerException.Message}");
//         }
//         return Page();
//     }
//     catch (Exception ex)
//     {
//         _logger.LogError(ex, "Unexpected error creating provider {ProviderName}.", ProviderInput.Name);
//         ModelState.AddModelError(string.Empty, "An unexpected error occurred. Please try again.");
//         return Page();
//     }
// }
 

//         /// <summary>
//         /// Handles the POST request to create a new provider.
//         /// Validates the input, checks for ShortCode uniqueness, creates the entity,
//         /// and saves it to the database.
//         /// </summary>
//         //     public async Task<IActionResult> OnPostAsync()
//         //     {
//         //         // if (!ModelState.IsValid)
//         //         // {
//         //         //     _logger.LogWarning("Create Provider POST: Model state is invalid.");
//         //         //     return Page(); // Re-display the form with validation errors
//         //         // }



//         // if (!ModelState.IsValid)
//         // {
//         //     _logger.LogWarning("Create Provider POST: Model state is invalid.");
//         //     return Page(); // Re-display the form with validation errors
//         // }


//         //         // Normalize ShortCode (e.g., to lowercase) if desired for consistency, before uniqueness check
//         //         // ProviderInput.ShortCode = ProviderInput.ShortCode.ToLowerInvariant();

//         //         // Check for ShortCode uniqueness
//         //         bool shortCodeExists = await _context.Providers
//         //                                     .AnyAsync(p => p.ShortCode == ProviderInput.ShortCode);
//         //         if (shortCodeExists)
//         //         {
//         //             _logger.LogWarning("Create Provider POST: ShortCode '{ShortCode}' already exists.", ProviderInput.ShortCode);
//         //             ModelState.AddModelError(nameof(ProviderViewModel.ShortCode), "This Short Code is already in use. Please choose another.");
//         //             return Page();
//         //         }

//         //         // Map ViewModel to Entity
//         //         var provider = new Provider
//         //         {
//         //             Id = Guid.NewGuid(), // Generate new ID for the provider
//         //             Name = ProviderInput.Name,
//         //             ShortCode = ProviderInput.ShortCode,
//         //             WebsiteDomain = ProviderInput.WebsiteDomain,
//         //             IsActive = ProviderInput.IsActive,
//         //             CreatedAt = DateTime.UtcNow,
//         //             UpdatedAt = DateTime.UtcNow
//         //         };

//         //         try
//         //         {
//         //             _context.Providers.Add(provider);
//         //             await _context.SaveChangesAsync();
//         //             _logger.LogInformation("Successfully created Provider: {ProviderName} (ID: {ProviderId}, ShortCode: {ProviderShortCode})",
//         //                 provider.Name, provider.Id, provider.ShortCode);

//         //             TempData["SuccessMessage"] = $"Provider '{provider.Name}' created successfully.";
//         //             return RedirectToPage("./Index"); // Redirect to the list of providers
//         //         }
//         //         catch (DbUpdateException ex)
//         //         {
//         //             // This might catch issues like unique constraint violations not caught above (if any other)
//         //             // or other database-related errors.
//         //             _logger.LogError(ex, "Error creating provider {ProviderName} in database.", ProviderInput.Name);
//         //             ModelState.AddModelError(string.Empty, "An error occurred while creating the provider. Please try again.");
//         //             // Check inner exception for more details, especially for constraint violations
//         //             if (ex.InnerException != null)
//         //             {
//         //                 _logger.LogError("Inner exception: {InnerExceptionMessage}", ex.InnerException.Message);
//         //                  ModelState.AddModelError(string.Empty, $"Database error: {ex.InnerException.Message}");
//         //             }
//         //             return Page(); // Re-display form with error
//         //         }
//         //         catch (Exception ex)
//         //         {
//         //             _logger.LogError(ex, "Unexpected error creating provider {ProviderName}.", ProviderInput.Name);
//         //             ModelState.AddModelError(string.Empty, "An unexpected error occurred. Please try again.");
//         //             return Page();
//         //         }
//         //     }
//     }
// }