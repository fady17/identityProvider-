// File: Orjnz.IdentityProvider.Web/Data/Provider.cs (or Models/Provider.cs)
using System;
using System.ComponentModel.DataAnnotations; // For Key attribute if not using fluent API

namespace Orjnz.IdentityProvider.Web.Data
{
    public class Provider
    {
        [Key] 
        public Guid Id { get; set; }

        [Required]
        [StringLength(200)]
        public required string Name { get; set; }

        [Required]
        [StringLength(50)] 
        public required string ShortCode { get; set; } // Must be unique if used for client_id/audience parts

        [StringLength(256)]
        public string? WebsiteDomain { get; set; }

        public bool IsActive { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
}