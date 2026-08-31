using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OAuthAuthentication.Models;

namespace OAuthAuthentication;

/// <summary>Performs OAuth 2.0 authorization-code/PKCE and refresh-token operations.</summary>
public class AuthenticationService : IAuthenticationService
{
    private static readonly HttpClient SharedHttpClient = new();
    private readonly OAuthOptions _options;
    private readonly string _codeVerifier;
    private readonly HttpClient _httpClient;
    private ProviderEndpoints? _endpoints;

    public AuthenticationService(OAuthOptions options)
        : this(options, Utilities.CodeVerifier.GenerateCodeVerifier(), null)
    {
    }

    public AuthenticationService(OAuthOptions options, string codeVerifier)
        : this(options, codeVerifier, null)
    {
    }

    /// <summary>Creates a service. The supplied HTTP client remains owned by the caller.</summary>
    public AuthenticationService(OAuthOptions options, string codeVerifier, HttpClient? httpClient)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        if (string.IsNullOrWhiteSpace(codeVerifier))
            throw new ArgumentException("A PKCE code verifier is required.", nameof(codeVerifier));

        _options = options;
        _codeVerifier = codeVerifier;
        _httpClient = httpClient ?? SharedHttpClient;
    }

    public async Task<Uri> GetConnectionLinkAsync(CancellationToken cancellationToken = default)
    {
        var endpoints = await GetEndpointsAsync(cancellationToken).ConfigureAwait(false);
        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = _options.ClientId,
            ["response_type"] = "code",
            ["scope"] = _options.Scopes,
            ["redirect_uri"] = _options.RedirectUri.ToString(),
            ["code_challenge"] = GenerateCodeChallenge(_codeVerifier),
            ["code_challenge_method"] = "S256"
        };

        var query = string.Join("&", parameters.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        var builder = new UriBuilder(endpoints.AuthorizationEndpoint)
        {
            Query = string.IsNullOrEmpty(endpoints.AuthorizationEndpoint.Query)
                ? query
                : $"{endpoints.AuthorizationEndpoint.Query.TrimStart('?')}&{query}"
        };
        return builder.Uri;
    }

    public async Task<TokenResponse> GetTokenFromAuthorizationCodeAsync(
        string authorizationCode,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(authorizationCode))
            throw new ArgumentException("The authorization code is required.", nameof(authorizationCode));

        var endpoints = await GetEndpointsAsync(cancellationToken).ConfigureAwait(false);
        return await RequestTokenAsync(endpoints.TokenEndpoint, new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authorizationCode,
            ["redirect_uri"] = _options.RedirectUri.ToString(),
            ["code_verifier"] = _codeVerifier
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<TokenResponse> GetTokenFromRefreshTokenAsync(
        string refreshToken,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
            throw new ArgumentException("The refresh token is required.", nameof(refreshToken));

        var endpoints = await GetEndpointsAsync(cancellationToken).ConfigureAwait(false);
        var result = await RequestTokenAsync(endpoints.TokenEndpoint, new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken
        }, cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(result.RefreshToken))
            result.RefreshToken = refreshToken;
        return result;
    }

    // Compatibility aliases for existing consumers.
    public Task<TokenResponse> GetTokenFromAuthorizationCode(string authorizationCode) =>
        GetTokenFromAuthorizationCodeAsync(authorizationCode);

    public Task<TokenResponse> GetTokenFromRefreshToken(string refreshToken) =>
        GetTokenFromRefreshTokenAsync(refreshToken);

    public static bool IsTokenValid(string? token) => IsTokenValid(token, TimeSpan.FromMinutes(1));

    public static bool IsTokenValid(string? token, TimeSpan clockSkew)
    {
        if (string.IsNullOrWhiteSpace(token) || clockSkew < TimeSpan.Zero)
            return false;
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return false;
            var payload = DecodeBase64Url(parts[1]);
            using var document = JsonDocument.Parse(payload);
            return document.RootElement.TryGetProperty("exp", out var expiration) &&
                   expiration.TryGetInt64(out var seconds) &&
                   DateTimeOffset.FromUnixTimeSeconds(seconds) > DateTimeOffset.UtcNow.Add(clockSkew);
        }
        catch (Exception) when (token is not null)
        {
            return false;
        }
    }

    private async Task<TokenResponse> RequestTokenAsync(
        Uri tokenEndpoint,
        IReadOnlyDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        var formValues = new Dictionary<string, string>(values);
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
        AddClientAuthentication(request, formValues);
        request.Content = new FormUrlEncodedContent(formValues);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<TokenResponse>(stream, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (result is null || string.IsNullOrWhiteSpace(result.AccessToken))
            throw new InvalidOperationException("The token response did not contain an access token.");
        return result;
    }

    private void AddClientAuthentication(HttpRequestMessage request, IDictionary<string, string> formValues)
    {
        switch (_options.TokenEndpointAuthenticationMethod)
        {
            case TokenEndpointAuthenticationMethod.ClientSecretPost:
                formValues["client_id"] = _options.ClientId;
                formValues["client_secret"] = _options.ClientSecret;
                break;
            case TokenEndpointAuthenticationMethod.ClientSecretBasic:
                var userName = WebUtility.UrlEncode(_options.ClientId);
                var password = WebUtility.UrlEncode(_options.ClientSecret);
                var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{userName}:{password}"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
                break;
            default:
                throw new InvalidOperationException(
                    $"Unsupported token endpoint authentication method: {_options.TokenEndpointAuthenticationMethod}.");
        }
    }

    private async Task<ProviderEndpoints> GetEndpointsAsync(CancellationToken cancellationToken)
    {
        if (_endpoints is not null) return _endpoints;
        Uri? authorization = _options.AuthorizationEndpoint;
        Uri? token = _options.TokenEndpoint;
        if (_options.DiscoveryEndpoint is not null && (authorization is null || token is null))
        {
            using var response = await _httpClient.GetAsync(_options.DiscoveryEndpoint, cancellationToken)
                .ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            authorization ??= ReadEndpoint(document.RootElement, "authorization_endpoint");
            token ??= ReadEndpoint(document.RootElement, "token_endpoint");
        }
        return _endpoints = new ProviderEndpoints(authorization!, token!);
    }

    private static Uri ReadEndpoint(JsonElement document, string propertyName)
    {
        if (!document.TryGetProperty(propertyName, out var value) ||
            !Uri.TryCreate(value.GetString(), UriKind.Absolute, out var endpoint))
            throw new InvalidOperationException($"The discovery document has no valid '{propertyName}'.");
        return endpoint;
    }

    private static string GenerateCodeChallenge(string verifier) =>
        Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    private static string DecodeBase64Url(string value) =>
        Encoding.UTF8.GetString(Convert.FromBase64String(
            value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '=')));

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private sealed record ProviderEndpoints(Uri AuthorizationEndpoint, Uri TokenEndpoint);
}
