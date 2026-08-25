using OAuthAuthentication.Models;

namespace OAuthAuthentication;

/// <summary>Reusable OAuth operations that do not depend on a UI framework.</summary>
public interface IAuthenticationService
{
    Task<Uri> GetConnectionLinkAsync(CancellationToken cancellationToken = default);

    Task<TokenResponse> GetTokenFromAuthorizationCodeAsync(
        string authorizationCode,
        CancellationToken cancellationToken = default);

    Task<TokenResponse> GetTokenFromRefreshTokenAsync(
        string refreshToken,
        CancellationToken cancellationToken = default);
}
