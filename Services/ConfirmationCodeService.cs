// File: Orjnz.IdentityProvider.Web/Services/ConfirmationCodeService.cs
using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace Orjnz.IdentityProvider.Web.Services
{
    public interface IConfirmationCodeService
    {
        Task<string> GenerateAndStoreCodeAsync(string userId, string actualToken, TimeSpan? expiration = null);
        Task<ConfirmationCodeData?> GetCodeDataAsync(string userId);
        Task<bool> ValidateCodeAsync(string userId, string enteredCode);
        Task InvalidateCodeAsync(string userId);
        Task<int> IncrementAttemptsAsync(string userId);
        Task ResetAttemptsAsync(string userId);
    }

    public class ConfirmationCodeData
    {
        public required string DisplayCode { get; set; }
        public required string ActualToken { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public int AttemptCount { get; set; }
        public bool IsExpired => DateTime.UtcNow > ExpiresAt;
        public bool IsMaxAttemptsReached => AttemptCount >= 3;
    }

    public class ConfirmationCodeService : IConfirmationCodeService
    {
        private readonly IDistributedCache _cache;
        private readonly ILogger<ConfirmationCodeService> _logger;
        private readonly TimeSpan _defaultExpiration = TimeSpan.FromMinutes(15);

        public ConfirmationCodeService(IDistributedCache cache, ILogger<ConfirmationCodeService> logger)
        {
            _cache = cache;
            _logger = logger;
        }

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
                _logger.LogError(ex, "Failed to deserialize confirmation code data for UserId {UserId}", userId);
                await _cache.RemoveAsync(cacheKey); // Remove corrupted data
                return null;
            }
        }

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

            return codeData.DisplayCode == enteredCode?.Trim();
        }

        public async Task InvalidateCodeAsync(string userId)
        {
            var cacheKey = GetCacheKey(userId);
            await _cache.RemoveAsync(cacheKey);
            _logger.LogInformation("Invalidated confirmation code for UserId {UserId}", userId);
        }

        public async Task<int> IncrementAttemptsAsync(string userId)
        {
            var codeData = await GetCodeDataAsync(userId);
            if (codeData == null)
            {
                return 0;
            }

            codeData.AttemptCount++;
            
            // Update the cache with incremented attempt count
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

            _logger.LogInformation("Incremented attempt count to {AttemptCount} for UserId {UserId}", codeData.AttemptCount, userId);
            return codeData.AttemptCount;
        }

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

        private static string GetCacheKey(string userId) => $"email_confirmation:{userId}";
    }

    // Extension method for service registration
    public static class ConfirmationCodeServiceExtensions
    {
        public static IServiceCollection AddConfirmationCodeService(this IServiceCollection services)
        {
            services.AddScoped<IConfirmationCodeService, ConfirmationCodeService>();
            return services;
        }
    }
}