using System.Text.Json.Serialization;

namespace OAuthAuthentication.Models;

/// <summary>Tokens and provider metadata returned by an OAuth token endpoint.</summary>
public class TokenResponse
{
    [JsonPropertyName("access_token")] 
    public string AccessToken { get; set; } = "";
    
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
    
    [JsonPropertyName("refresh_expires_in")]
    public int RefreshExpiresIn { get; set; }
    
    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;
    
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = string.Empty;
    
    [JsonPropertyName("id_token")]
    public string IdToken { get; set; } = string.Empty;
    
    [JsonPropertyName("not-before-policy")]
    public int NotBeforePolicy { get; set; }
    
    [JsonPropertyName("session_state")]
    public string SessionState { get; set; } = string.Empty;
    
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;
}
