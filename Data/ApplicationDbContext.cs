using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;

namespace Orjnz.IdentityProvider.Web.Data
{
    /// <summary>
    /// The Entity Framework Core database context for the application.
    /// It serves as the primary bridge between the application's C# entity models and the database.
    /// This context inherits from IdentityDbContext to include schemas for ASP.NET Core Identity
    /// and is configured to also manage OpenIddict entities.
    /// </summary>
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
    {
        /// <summary>
        /// The collection of <see cref="Provider"/> entities in the database.
        /// </summary>
        public DbSet<Provider> Providers { get; set; }

        // Note: DbSets for OpenIddict entities (e.g., AppCustomOpenIddictApplication) are not explicitly
        // declared here. They are managed implicitly by OpenIddict's EF Core integration when
        // `options.UseOpenIddict()` is called during DbContext configuration in Program.cs.

        /// <summary>
        /// Initializes a new instance of the <see cref="ApplicationDbContext"/> class.
        /// </summary>
        /// <param name="options">The options to be used by a DbContext.</param>
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        /// <summary>
        /// Configures the schema needed for the identity and custom entities in the database.
        /// </summary>
        /// <param name="builder">The builder being used to construct the model for this context.</param>
        protected override void OnModelCreating(ModelBuilder builder)
        {
            // IMPORTANT: This call is required to configure the schema for ASP.NET Core Identity entities.
            // It must be called before any custom configurations are applied.
            base.OnModelCreating(builder);

            // --- Custom Provider Entity Configuration ---
            builder.Entity<Provider>(entity =>
            {
                // Define constraints and indexes for the Provider entity.
                entity.Property(p => p.Name).IsRequired().HasMaxLength(200);
                entity.Property(p => p.ShortCode).IsRequired().HasMaxLength(50);
                // Enforce uniqueness on the ShortCode property at the database level.
                entity.HasIndex(p => p.ShortCode).IsUnique();
                entity.Property(p => p.WebsiteDomain).HasMaxLength(256);
            });

            // --- Configure Relationship between AppCustomOpenIddictApplication and Provider ---
            // This configuration defines the foreign key relationship from our custom OpenIddict application
            // entity to our custom Provider entity.
            builder.Entity<AppCustomOpenIddictApplication>(application =>
            {
                // Defines a one-to-many relationship: one Provider can have many Applications.
                application.HasOne(a => a.Provider)
                           .WithMany() // No corresponding navigation property on Provider needed.
                           .HasForeignKey(a => a.ProviderId)
                           .IsRequired(false) // The ProviderId is optional (an application might not belong to a provider).
                           .OnDelete(DeleteBehavior.SetNull); // If a Provider is deleted, set the ProviderId on related applications to NULL.

                // Creates a database index on the ProviderId foreign key for improved query performance.
                application.HasIndex(a => a.ProviderId)
                           .HasDatabaseName("IX_OpenIddictApplications_ProviderId");
            });

            // Future entity configurations for other custom OpenIddict entities would be placed here.
            // For example: builder.Entity<AppCustomOpenIddictScope>(scope => { ... });
        }
    }
}