# OAuthAuthentication

Reusable OAuth 2.0 authorization-code/PKCE logic with no UI or application-settings dependency.

```csharp
using OAuthAuthentication;
using OAuthAuthentication.Utilities;

var options = new OAuthOptions
{
    ClientId = "my-client",
    RedirectUri = new Uri("https://app.example/callback"),
    Scopes = "openid profile offline_access",
    DiscoveryEndpoint = new Uri("https://identity.example/.well-known/openid-configuration")
};

var verifier = CodeVerifier.GenerateCodeVerifier();
IAuthenticationService authentication = new AuthenticationService(options, verifier);
var authorizationUrl = await authentication.GetConnectionLinkAsync();
```

The application opens `authorizationUrl` in its own browser/WebView. After receiving the redirect:

```csharp
var tokens = await authentication.GetTokenFromAuthorizationCodeAsync(code);
var refreshed = await authentication.GetTokenFromRefreshTokenAsync(tokens.RefreshToken);
bool valid = AuthenticationService.IsTokenValid(refreshed.AccessToken);
```

Keep the same service instance (and therefore the same PKCE verifier) between URL generation and
the authorization-code exchange. Consumers own UI, persistence, logging, and secret storage.
