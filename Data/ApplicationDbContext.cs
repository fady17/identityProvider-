using Microsoft.AspNetCore.Identity.EntityFrameworkCore; // For IdentityDbContext
using Microsoft.AspNetCore.Identity; // For IdentityUserLogin, IdentityUserRole etc. if needed for explicit config
using Microsoft.EntityFrameworkCore;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For your custom entities

namespace Orjnz.IdentityProvider.Web.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
    {
        public DbSet<Provider> Providers { get; set; } // Your custom Provider entity



        // DbSets for OpenIddict entities (AppCustomOpenIddictApplication, etc.)
        // will be implicitly managed by OpenIddict when you call UseEntityFrameworkCore()
        // and ReplaceDefaultEntities() in Program.cs. You generally do not need
        // to declare DbSet<AppCustomOpenIddictApplication> Applications { get; set; } here.
        // OpenIddict registers its own generic OpenIddictEntityFrameworkCoreContext<..., TKey>
        // internally or expects the DbContext you provide to be configurable for its entities.

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            // IMPORTANT: Call base.OnModelCreating first.
            // This executes the OnModelCreating method from IdentityDbContext,
            // applying all its default configurations for Identity entities.
            base.OnModelCreating(builder);

            // --- Custom Provider Entity Configuration ---
            builder.Entity<Provider>(entity =>
            {
                // Primary Key is usually inferred by convention if property is named Id or <Type>Id,
                // or by [Key] attribute. Explicitly defining it is also fine.
                // entity.HasKey(p => p.Id); // Already defined by [Key] attribute in Provider.cs

                entity.Property(p => p.Name).IsRequired().HasMaxLength(200);
                entity.Property(p => p.ShortCode).IsRequired().HasMaxLength(50);
                entity.HasIndex(p => p.ShortCode).IsUnique(); // Ensure ShortCode is unique
                entity.Property(p => p.WebsiteDomain).HasMaxLength(256);
            });

            // --- Configure Relationship between AppCustomOpenIddictApplication and Provider ---
            // Also, configure any other specific needs for AppCustomOpenIddictApplication.
            // Even though DbSets for OpenIddict entities are not explicitly declared here,
            // EF Core can still configure entities if they are discoverable
            // (e.g., through navigation properties or explicit builder.Entity<T>() calls).
            // The .ReplaceDefaultEntities() call in Program.cs will make OpenIddict aware of these types.
            builder.Entity<AppCustomOpenIddictApplication>(application =>
            {
                // The table name for OpenIddict applications is typically "OpenIddictApplications".
                // This is handled by OpenIddict's .UseEntityFrameworkCore().
                // If you needed to override:
                // application.ToTable("YourCustomApplicationsTableName");

                application.HasOne(a => a.Provider)
                           .WithMany()
                           .HasForeignKey(a => a.ProviderId)
                           .IsRequired(false)
                           .OnDelete(DeleteBehavior.SetNull);

                application.HasIndex(a => a.ProviderId)
                           .HasDatabaseName("IX_OpenIddictApplications_ProviderId");
            });

            // If you add custom properties to AppCustomOpenIddictAuthorization, AppCustomOpenIddictScope,
            // or AppCustomOpenIddictToken in the future that require Fluent API configuration,
            // you would add them here using builder.Entity<AppCustomOpenIddictAuthorization>(auth => { ... }); etc.
            // For example, if AppCustomOpenIddictScope had a property:
            // builder.Entity<AppCustomOpenIddictScope>(scope =>
            // {
            //     scope.Property(s => s.SomeCustomScopeProperty).HasMaxLength(100);
            // });
        }
    }
}