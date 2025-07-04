using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Defines the contract for a service that manages short-lived, user-friendly confirmation codes.
    /// This is typically used for two-factor authentication or email confirmation flows where a simple
    /// numeric code is preferred over a long, complex token URL.
    /// </summary>
    public interface IConfirmationCodeService
    {
        /// <summary>
        /// Generates a new display code (e.g., "123456"), associates it with a secure underlying token,
        /// and stores it in a distributed cache with an expiration.
        /// </summary>
        /// <param name="userId">The unique identifier of the user for whom the code is generated.</param>
        /// <param name="actualToken">The secure, underlying token (e.g., from ASP.NET Core Identity's token provider).</param>
        /// <param name="expiration">The duration for which the code is valid. Uses a default if not provided.</param>
        /// <returns>The user-friendly display code.</returns>
        Task<string> GenerateAndStoreCodeAsync(string userId, string actualToken, TimeSpan? expiration = null);

        /// <summary>
        /// Retrieves the stored data associated with a user's confirmation code.
        /// </summary>
        /// <param name="userId">The user's unique identifier.</param>
        /// <returns>The <see cref="ConfirmationCodeData"/> if found and valid; otherwise, <c>null</c>.</returns>
        Task<ConfirmationCodeData?> GetCodeDataAsync(string userId);

        /// <summary>
        /// Validates a user-entered code against the stored data.
        /// </summary>
        /// <param name="userId">The user's unique identifier.</param>
        /// <param name="enteredCode">The code entered by the user.</param>
        /// <returns><c>true</c> if the code is valid, not expired, and within the attempt limit; otherwise, <c>false</c>.</returns>
        Task<bool> ValidateCodeAsync(string userId, string enteredCode);

        /// <summary>
        /// Removes the confirmation code data from the cache, effectively invalidating it.
        /// </summary>
        /// <param name="userId">The user's unique identifier.</param>
        Task InvalidateCodeAsync(string userId);

        /// <summary>
        /// Increments the failed attempt counter for a user's confirmation code.
        /// </summary>
        /// <param name="userId">The user's unique identifier.</param>
        /// <returns>The new attempt count.</returns>
        Task<int> IncrementAttemptsAsync(string userId);

        /// <summary>
        /// Resets the attempt counter for a user's confirmation code back to zero.
        /// </summary>
        /// <param name="userId">The user's unique identifier.</param>
        Task ResetAttemptsAsync(string userId);
    }

    /// <summary>
    /// Represents the data structure stored in the cache for a confirmation code.
    /// </summary>
    public class ConfirmationCodeData
    {
        /// <summary>The simple, user-friendly code (e.g., "123456").</summary>
        public required string DisplayCode { get; set; }
        /// <summary>The secure, underlying token that this code represents.</summary>
        public required string ActualToken { get; set; }
        /// <summary>The timestamp when the code was created.</summary>
        public DateTime CreatedAt { get; set; }
        /// <summary>The timestamp when the code will expire.</summary>
        public DateTime ExpiresAt { get; set; }
        /// <summary>The number of failed validation attempts.</summary>
        public int AttemptCount { get; set; }
        /// <summary>Indicates if the code is past its expiration time.</summary>
        public bool IsExpired => DateTime.UtcNow > ExpiresAt;
        /// <summary>Indicates if the maximum number of validation attempts has been reached.</summary>
        public bool IsMaxAttemptsReached => AttemptCount >= 3;
    }
    
    /// <summary>
    /// Implements the logic for managing confirmation codes using a distributed cache.
    /// </summary>
    public class ConfirmationCodeService : IConfirmationCodeService
    {
        private readonly IDistributedCache _cache;
        private readonly ILogger<ConfirmationCodeService> _logger;
        private readonly TimeSpan _defaultExpiration = TimeSpan.FromMinutes(15);

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfirmationCodeService"/> class.
        /// </summary>
        /// <param name="cache">The distributed cache for storing code data.</param>
        /// <param name="logger">The logger for recording service operations.</param>
        public ConfirmationCodeService(IDistributedCache cache, ILogger<ConfirmationCodeService> logger)
        {
            _cache = cache;
            _logger = logger;
        }

        /// <inheritdoc/>
        public async Task<string> GenerateAndStoreCodeAsync(string userId, string actualToken, TimeSpan? expiration = null)
        {
            var exp = expiration ?? _defaultExpiration;
            var random = new Random();
            var displayCode = random.Next(100000, 999999).ToString("D6");
            
            var codeData = new ConfirmationCodeData
            {
                DisplayCode = displayCode,
                ActualToken = actualToken,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.Add(exp),
                AttemptCount = 0
            };

            var cacheKey = GetCacheKey(userId);
            var serializedData = JsonSerializer.Serialize(codeData);
            
            var cacheOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = exp
            };

            await _cache.SetStringAsync(cacheKey, serializedData, cacheOptions);
            _logger.LogInformation("Generated and stored confirmation code for UserId {UserId}, expires at {ExpiresAt}", userId, codeData.ExpiresAt);
            
            return displayCode;
        }

        /// <inheritdoc/>
        public async Task<ConfirmationCodeData?> GetCodeDataAsync(string userId)
        {
            var cacheKey = GetCacheKey(userId);
            var serializedData = await _cache.GetStringAsync(cacheKey);
            
            if (string.IsNullOrEmpty(serializedData))
            {
                return null;
            }

            try
            {
                return JsonSerializer.Deserialize<ConfirmationCodeData>(serializedData);
            }
            catch (JsonException ex)
            {
                // If data is corrupted, log the error and remove the invalid entry.
                _logger.LogError(ex, "Failed to deserialize confirmation code data for UserId {UserId}", userId);
                await _cache.RemoveAsync(cacheKey);
                return null;
            }
        }

        /// <inheritdoc/>
        public async Task<bool> ValidateCodeAsync(string userId, string enteredCode)
        {
            var codeData = await GetCodeDataAsync(userId);
            
            if (codeData == null)
            {
                _logger.LogWarning("No confirmation code data found for UserId {UserId}", userId);
                return false;
            }

            if (codeData.IsExpired)
            {
                _logger.LogWarning("Confirmation code expired for UserId {UserId}", userId);
                await InvalidateCodeAsync(userId);
                return false;
            }

            if (codeData.IsMaxAttemptsReached)
            {
                _logger.LogWarning("Max attempts reached for confirmation code for UserId {UserId}", userId);
                return false;
            }

            // Compare the user-provided code with the stored display code.
            return codeData.DisplayCode == enteredCode?.Trim();
        }

        /// <inheritdoc/>
        public async Task InvalidateCodeAsync(string userId)
        {
            var cacheKey = GetCacheKey(userId);
            await _cache.RemoveAsync(cacheKey);
            _logger.LogInformation("Invalidated confirmation code for UserId {UserId}", userId);
        }

        /// <inheritdoc/>
        public async Task<int> IncrementAttemptsAsync(string userId)
        {
            var codeData = await GetCodeDataAsync(userId);
            if (codeData == null)
            {
                return 0;
            }

            codeData.AttemptCount++;
            
            // Update the data in the cache with the new attempt count.
            var cacheKey = GetCacheKey(userId);
            var serializedData = JsonSerializer.Serialize(codeData);
            var remainingTime = codeData.ExpiresAt - DateTime.UtcNow;
            
            // Ensure we don't try to set a cache item with a negative expiration.
            if (remainingTime > TimeSpan.Zero)
            {
                var cacheOptions = new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = remainingTime
                };
                await _cache.SetStringAsync(cacheKey, serializedData, cacheOptions);
            }

            _logger.LogInformation("Incremented attempt count to {AttemptCount} for UserId {UserId}", codeData.AttemptCount, userId);
            return codeData.AttemptCount;
        }

        /// <inheritdoc/>
        public async Task ResetAttemptsAsync(string userId)
        {
            var codeData = await GetCodeDataAsync(userId);
            if (codeData == null)
            {
                return;
            }

            codeData.AttemptCount = 0;
            
            var cacheKey = GetCacheKey(userId);
            var serializedData = JsonSerializer.Serialize(codeData);
            var remainingTime = codeData.ExpiresAt - DateTime.UtcNow;
            
            if (remainingTime > TimeSpan.Zero)
            {
                var cacheOptions = new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = remainingTime
                };
                await _cache.SetStringAsync(cacheKey, serializedData, cacheOptions);
            }

            _logger.LogInformation("Reset attempt count for UserId {UserId}", userId);
        }

        /// <summary>
        /// Generates a consistent cache key for a given user ID.
        /// </summary>
        private static string GetCacheKey(string userId) => $"email_confirmation:{userId}";
    }

    /// <summary>
    /// Provides an extension method to register the <see cref="IConfirmationCodeService"/>
    /// and its implementation with the dependency injection container.
    /// </summary>
    public static class ConfirmationCodeServiceExtensions
    {
        /// <summary>
        /// Adds the <see cref="IConfirmationCodeService"/> to the service collection.
        /// </summary>
        public static IServiceCollection AddConfirmationCodeService(this IServiceCollection services)
        {
            services.AddScoped<IConfirmationCodeService, ConfirmationCodeService>();
            return services;
        }
    }
}