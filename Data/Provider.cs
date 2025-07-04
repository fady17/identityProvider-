using System;
using System.ComponentModel.DataAnnotations;

namespace Orjnz.IdentityProvider.Web.Data
{
    /// <summary>
    /// Represents a healthcare provider or a tenant organization in the system.
    /// Each provider can have its own set of users and client applications.
    /// </summary>
    public class Provider
    {
        /// <summary>
        /// The unique identifier for the provider.
        /// </summary>
        [Key]
        public Guid Id { get; set; }

        /// <summary>
        /// The full name of the provider or organization.
        /// </summary>
        [Required]
        [StringLength(200)]
        public required string Name { get; set; }

        /// <summary>
        /// A short, unique code for the provider. This can be used in routing, claims, or client identifiers.
        /// </summary>
        [Required]
        [StringLength(50)]
        public required string ShortCode { get; set; }

        /// <summary>
        /// The primary website domain associated with the provider, used for informational purposes.
        /// </summary>
        [StringLength(256)]
        public string? WebsiteDomain { get; set; }

        /// <summary>
        /// Indicates whether the provider's record is active.
        /// </summary>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// The timestamp when the provider record was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// The timestamp when the provider record was last updated.
        /// </summary>
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
}