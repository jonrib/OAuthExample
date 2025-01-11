using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OAuthExample;
using OAuthExample.Persistence;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Client.WebIntegration;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(
        policy  =>
        {
            policy.AllowAnyOrigin();
            policy.AllowAnyHeader();
        });
});

builder.Services.AddAuthentication(options => {options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;})
    .AddCookie("ExternalLogin", options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(1);
        options.SlidingExpiration = false;
        options.Cookie.MaxAge = TimeSpan.FromMinutes(1);
    });
builder.Services.AddAuthorization(opt =>
{
    opt.InvokeHandlersAfterFailure = false;
});

// Worker for seeding DB
builder.Services.AddHostedService<Worker>();

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer("Server=JONAS\\SQLEXPRESS;Integrated Security=true;TrustServerCertificate=True;");
    options.UseOpenIddict();
});

//OpenIddict stuffs
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<AppDbContext>();
    })
    .AddClient(options =>
    {
        options.AllowAuthorizationCodeFlow();
        
        // For DEV only
        options.AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();
        
        options.UseAspNetCore()
            .EnableRedirectionEndpointPassthrough();
        
        options.UseSystemNetHttp();
        
        options.SetStateTokenLifetime(TimeSpan.FromMinutes(1));
        
        options.UseWebProviders()
            .AddGitHub(options =>
            {
                options.SetClientId("Ov23lize03OCXfRuoFtj")
                    .SetClientSecret("3a4ef54a546f234375de1f27cee5c7c60eba9575")
                    .SetRedirectUri("callback/login/github");
            });
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token")
            .SetUserInfoEndpointUris("connect/userinfo");

        // Mark the "email" scopes as supported scope.
        options.RegisterScopes(OpenIddictConstants.Scopes.Email);
        
        options.AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowRefreshTokenFlow();
        
        options.AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        options.DisableAccessTokenEncryption();
        
        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

var app = builder.Build();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
    {
        var forecast = Enumerable.Range(1, 5).Select(index =>
                new WeatherForecast
                (
                    DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                    Random.Shared.Next(-20, 55),
                    summaries[Random.Shared.Next(summaries.Length)]
                ))
            .ToArray();
        return forecast;
    })
    .RequireAuthorization()
    .WithName("GetWeatherForecast")
    .WithOpenApi();

app.MapGet("/connect/authorize", Authorize);
app.MapPost("/connect/authorize", Authorize);
app.MapGet("/callback/login/{provider}", LogInCallback);
app.MapPost("/callback/login/{provider}", LogInCallback);
app.MapPost("/connect/token", Exchange);

async Task LogInCallback(HttpContext context)
{
    var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
    
    if (result.Principal is not { Identity.IsAuthenticated: true })
    {
        throw new InvalidOperationException("The external authorization data cannot be used for authentication.");
    }
    
    var identity = new ClaimsIdentity(authenticationType: "ExternalLogin");
    
    identity
        .SetClaim("login", result.Principal.GetClaim("login"))
            .SetClaim(ClaimTypes.Email, result.Principal.GetClaim(ClaimTypes.Email))
            .SetClaim(ClaimTypes.Name, result.Principal.GetClaim(ClaimTypes.Name))
            .SetClaim(ClaimTypes.NameIdentifier, result.Principal.GetClaim(ClaimTypes.NameIdentifier));
    
    var properties = new AuthenticationProperties(result.Properties.Items)
    {
        RedirectUri = result.Properties.RedirectUri ?? "/"
    };
    
    properties.StoreTokens(result.Properties.GetTokens().Where(token => token.Name is
        OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken   or
        OpenIddictClientAspNetCoreConstants.Tokens.BackchannelIdentityToken or
        OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken));
    
    await context.SignInAsync("ExternalLogin", new ClaimsPrincipal(identity), properties);
}

async Task Authorize(HttpContext context)
{
    var request = context.GetOpenIddictServerRequest() ??
                  throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
    
    var result = await context.AuthenticateAsync("ExternalLogin");
    if (!result.Succeeded)
    {
        await context.ChallengeAsync(OpenIddictClientWebIntegrationConstants.Providers.GitHub);
        return;
    }
    
    var identity = new ClaimsIdentity(
        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
        nameType: OpenIddictConstants.Claims.Name,
        roleType: OpenIddictConstants.Claims.Role);
    
    identity.SetClaim(OpenIddictConstants.Claims.Subject, result.Principal.GetClaim("login"))
        .SetClaim(OpenIddictConstants.Claims.Email, result.Principal.GetClaim(ClaimTypes.Email))
        .SetClaim(OpenIddictConstants.Claims.Name, result.Principal.GetClaim(ClaimTypes.Name));
    
    // In reality should be limited...
    identity.SetScopes(request.GetScopes());
    
    var principal = new ClaimsPrincipal(identity);
    
    var ticket = new AuthenticationTicket(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

    await context.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, ticket.Properties);
}

async Task Exchange(HttpContext context)
{
    var request = context.GetOpenIddictServerRequest() ??
                  throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

    if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
    {
        // Retrieve the claims principal stored in the authorization code/refresh token.
        var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var identity = new ClaimsIdentity(result.Principal.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: OpenIddictConstants.Claims.Name,
            roleType: OpenIddictConstants.Claims.Role);

        // Override the user claims present in the principal in case they
        // changed since the authorization code/refresh token was issued.
        identity.SetClaim(OpenIddictConstants.Claims.Subject, result.Principal.GetClaim(OpenIddictConstants.Claims.Subject))
            .SetClaim(OpenIddictConstants.Claims.Email, result.Principal.GetClaim(OpenIddictConstants.Claims.Email))
            .SetClaim(OpenIddictConstants.Claims.Name, result.Principal.GetClaim(OpenIddictConstants.Claims.Name));
        
        var principal = new ClaimsPrincipal(identity);
    
        var ticket = new AuthenticationTicket(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        await context.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, ticket.Properties);
        return;
    }

    throw new InvalidOperationException("The specified grant type is not supported.");
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors();

app.UseHttpsRedirection();

app.UseDeveloperExceptionPage();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}