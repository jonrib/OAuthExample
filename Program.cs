using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OAuthExample;
using OAuthExample.Persistence;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(options => {options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;});
builder.Services.AddAuthorization(opt =>
{
    opt.InvokeHandlersAfterFailure = false;
});

// Register the worker responsible for seeding the database.
// Note: in a real world application, this step should be part of a setup script.
builder.Services.AddHostedService<Worker>();

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer("Server=JONAS\\SQLEXPRESS;Integrated Security=true;TrustServerCertificate=True;");
    options.UseOpenIddict();
});

builder.Services.AddOpenIddict()

    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        // Configure OpenIddict to use the Entity Framework Core stores and models.
        // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
        options.UseEntityFrameworkCore()
            .UseDbContext<AppDbContext>();
    })

    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        // Enable the authorization, logout, token and userinfo endpoints.
        options.SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token")
            .SetUserInfoEndpointUris("connect/userinfo");

        // Mark the "email", "profile" and "roles" scopes as supported scopes.
        options.RegisterScopes(OpenIddictConstants.Scopes.Email, OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Roles);

        // Note: the sample uses the code and refresh token flows but you can enable
        // the other flows if you need to support implicit, password or client credentials.
        options.AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowRefreshTokenFlow();

        // Register the signing and encryption credentials.
        options.AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        options.DisableAccessTokenEncryption();
        
        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough();
    })

    // Register the OpenIddict validation components.
    .AddValidation(options =>
    {
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();

        // Register the ASP.NET Core host.
        options.UseAspNetCore();
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

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

app.MapGet("/connect/authorize", Authorize)
    .WithOpenApi();
app.MapPost("/connect/authorize", Authorize)
    .WithOpenApi();

async Task Authorize(HttpContext context)
{
    var request = context.GetOpenIddictServerRequest() ??
                  throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
    
    var result = await context.AuthenticateAsync();
    if (!result.Succeeded || request.HasPromptValue(OpenIddictConstants.PromptValues.Login) ||
        (request.MaxAge != null && result.Properties?.IssuedUtc != null &&
         DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value)))
    {
        // If the client application requested promptless authentication,
        // return an error indicating that the user is not logged in.
        if (request.HasPromptValue(OpenIddictConstants.PromptValues.None))
        {
            await context.ForbidAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.LoginRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                }!));
            return;
        }

        // To avoid endless login -> authorization redirects, the prompt=login flag
        // is removed from the authorization request payload before redirecting the user.
        var prompt = string.Join(" ", request.GetPromptValues().Remove(OpenIddictConstants.PromptValues.Login));

        var parameters = context.Request.HasFormContentType
            ? context.Request.Form.Where(parameter => parameter.Key != OpenIddictConstants.Parameters.Prompt).ToList()
            : context.Request.Query.Where(parameter => parameter.Key != OpenIddictConstants.Parameters.Prompt).ToList();

        parameters.Add(KeyValuePair.Create(OpenIddictConstants.Parameters.Prompt, new StringValues(prompt)));

        // For scenarios where the default challenge handler configured in the ASP.NET Core
        // authentication options shouldn't be used, a specific scheme can be specified here.
        await context.ChallengeAsync(new AuthenticationProperties
        {
            RedirectUri = context.Request.PathBase + context.Request.Path + QueryString.Create(parameters)
        });
        return;
    }


    // Create the claims-based identity that will be used by OpenIddict to generate tokens.
    var identity = new ClaimsIdentity(
        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
        nameType: OpenIddictConstants.Claims.Name,
        roleType: OpenIddictConstants.Claims.Role);

    // Add the claims that will be persisted in the tokens.
    identity.SetClaim(OpenIddictConstants.Claims.Subject, "Test")
        .SetClaim(OpenIddictConstants.Claims.Email, "Test")
        .SetClaim(OpenIddictConstants.Claims.Name, "Test")
        .SetClaim(OpenIddictConstants.Claims.PreferredUsername, "test")
        .SetClaims(OpenIddictConstants.Claims.Role, ["test"]);

    // Note: in this sample, the granted scopes match the requested scope
    // but you may want to allow the user to uncheck specific scopes.
    // For that, simply restrict the list of scopes before calling SetScopes.
    identity.SetScopes(request.GetScopes());
    
    var principal = new ClaimsPrincipal(identity);
    
    var ticket = new AuthenticationTicket(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

    await context.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, ticket.Properties);
}

app.MapPost("/connect/token", Exchange)
    .WithOpenApi();

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
        identity.SetClaim(OpenIddictConstants.Claims.Subject, "test")
            .SetClaim(OpenIddictConstants.Claims.Email, "test")
            .SetClaim(OpenIddictConstants.Claims.Name, "test")
            .SetClaim(OpenIddictConstants.Claims.PreferredUsername, "test")
            .SetClaims(OpenIddictConstants.Claims.Role, ["test"]);

        // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        var principal = new ClaimsPrincipal(identity);
    
        var ticket = new AuthenticationTicket(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        await context.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, ticket.Properties);
        return;
    }

    throw new InvalidOperationException("The specified grant type is not supported.");
}

app.UseAuthentication();
app.UseAuthorization();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}