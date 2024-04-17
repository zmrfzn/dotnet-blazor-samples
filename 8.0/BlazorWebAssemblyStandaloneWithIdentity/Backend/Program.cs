using System.Data;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Backend;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using OpenTelemetry.Instrumentation.AspNetCore;
using System.Diagnostics.Metrics;
using System.Diagnostics;

var builder = WebApplication.CreateBuilder(args);

// OpemTelemetry init (start)
DiagnosticsConfig.logger.LogInformation(eventId: 123, "Getting started!");

// Add OpenTelemetry Traces and Metrics to our Service Collection
builder.Services.AddOpenTelemetry()
    .WithTracing(tracerProviderBuilder =>
        tracerProviderBuilder
            .AddSource(DiagnosticsConfig.ActivitySource.Name)
            .ConfigureResource(resource => resource
                .AddService(DiagnosticsConfig.ServiceName))
            .AddAspNetCoreInstrumentation()
            //.AddConsoleExporter()
            .AddOtlpExporter()/*options =>
    {
        options.Endpoint = new Uri("https://otlp.nr-data.net");
        options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
        options.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
    })*/
        )
    .WithMetrics(metricsProviderBuilder =>
        metricsProviderBuilder
            .ConfigureResource(resource => resource
                .AddService(DiagnosticsConfig.ServiceName))
            .AddAspNetCoreInstrumentation()
            //.AddConsoleExporter()
            .AddMeter(DiagnosticsConfig.Meter.Name)
            .AddMeter("System.Net.Http")
            .AddMeter("Microsoft.AspNetCore.Hosting")
            .AddMeter("Microsoft.AspNetCore.Server.Kestrel")
            .AddOtlpExporter()/*options =>
    {
        options.Endpoint = new Uri("https://otlp.nr-data.net");
        options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
        options.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
    })*/
        );

string ServiceName = "BlazorWebAssemblyStandaloneWithIdentityBackend";
//builder.Logging.SetMinimumLevel(LogLevel.Debug);
builder.Services.AddLogging(builder =>
{
    builder.AddOpenTelemetry(options =>
    {
        //options.AddConsoleExporter();
        options.AddOtlpExporter(
    options =>
    {
        options.Endpoint = new Uri("https://otlp.nr-data.net");
        options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
        options.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
    });
        options.SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(
            serviceName: ServiceName,
            serviceVersion: "0.0.1"));
    });
}
            );
// Add OpenTelemetry Logs to our Service Collection
/*builder.Logging.AddOpenTelemetry(x =>
{
    x.SetResourceBuilder(ResourceBuilder.CreateDefault().AddService("MyService"));
    x.IncludeFormattedMessage = true;
    x.IncludeScopes = true;
    x.ParseStateValues = true;
    x.AddOtlpExporter();
});*/

//Console.WriteLine("Done with Otel config ...");
DiagnosticsConfig.logger.LogInformation(eventId: 123, "Done with Otel config ...");
// OpemTelemetry init (end)

// Establish cookie authentication
builder.Services.AddAuthentication(IdentityConstants.ApplicationScheme).AddIdentityCookies();

// Configure app cookie
//
// The default values, which are appropriate for hosting the Backend and
// BlazorWasmAuth apps on the same domain, are Lax and SameAsRequest. 
// For more information on these settings, see:
// https://learn.microsoft.com/aspnet/core/blazor/security/webassembly/standalone-with-identity#cross-domain-hosting-same-site-configuration
/*
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});
*/

// Configure authorization
builder.Services.AddAuthorizationBuilder();

// Add the database (in memory for the sample)
builder.Services.AddDbContext<AppDbContext>(
    options =>
    {
        options.UseInMemoryDatabase("AppDb");
        //For debugging only: options.EnableDetailedErrors(true);
        //For debugging only: options.EnableSensitiveDataLogging(true);
    });

// Add identity and opt-in to endpoints
builder.Services.AddIdentityCore<AppUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddApiEndpoints();

// Add a CORS policy for the client
builder.Services.AddCors(
    options => options.AddPolicy(
        "wasm",
        policy => policy.WithOrigins([builder.Configuration["BackendUrl"] ?? "https://localhost:5001",
            builder.Configuration["FrontendUrl"] ?? "https://localhost:5002"])
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials()
            .WithExposedHeaders("*")));


// Add services to the container
builder.Services.AddEndpointsApiExplorer();

// Add NSwag services
builder.Services.AddOpenApiDocument();

var app = builder.Build();

if (builder.Environment.IsDevelopment())
{
    // Seed the database
    await using var scope = app.Services.CreateAsyncScope();
    await SeedData.InitializeAsync(scope.ServiceProvider);

    // Add OpenAPI/Swagger generator and the Swagger UI
    app.UseOpenApi();
    app.UseSwaggerUi();
}

// Create routes for the identity endpoints
app.MapIdentityApi<AppUser>();

// Activate the CORS policy
app.UseCors("wasm");

// Enable authentication and authorization after CORS Middleware
// processing (UseCors) in case the Authorization Middleware tries
// to initiate a challenge before the CORS Middleware has a chance
// to set the appropriate headers.
app.UseAuthentication();
app.UseAuthorization();

ActivitySource MyLibraryActivitySource = new(
                "MyCompany.MyProduct.MyLibrary");
// Provide an end point to clear the cookie for logout
//
// For more information on the logout endpoint and antiforgery, see:
// https://learn.microsoft.com/aspnet/core/blazor/security/webassembly/standalone-with-identity#antiforgery-support
app.MapPost("/logout", async (SignInManager<AppUser> signInManager, [FromBody] object empty) => //, [FromHeader] object data) =>
{
    DiagnosticsConfig.logger.LogInformation(eventId: 123, "Entering logout");
    //DiagnosticsConfig.logger.LogInformation(eventId: 123, "Entering logout - header: " + data);
    // todo: look for trace id, if found, comntinue trace with new span
    var tracerProvider = Sdk.CreateTracerProviderBuilder()
                // The following adds subscription to activities from Activity Source
                // named "MyCompany.MyProduct.MyLibrary" only.
                .AddSource("MyCompany.MyProduct.MyLibrary")

                // The following adds subscription to activities from all Activity Sources
                // whose name starts with "AbcCompany.XyzProduct.".
                .AddSource("AbcCompany.XyzProduct.*")
                .ConfigureResource(resource => resource.AddAttributes(new List<KeyValuePair<string, object>>
                    {
                        new KeyValuePair<string, object>("static-attribute1", "v1"),
                        new KeyValuePair<string, object>("static-attribute2", "v2"),
                    }))
                .ConfigureResource(resource => resource.AddService("BlazorWebAssemblyStandaloneWithIdentityBackend"))
                .AddConsoleExporter()
                .AddOtlpExporter(options =>
    {
        options.Endpoint = new Uri("https://otlp.nr-data.net");
        options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
        //options.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
    })
    .Build();

    // This activity source is enabled.
    using (var activity = MyLibraryActivitySource.StartActivity("Logout"))
    {
        activity?.SetTag("foo", 1);
        activity?.SetTag("bar", "Hello, World!");
    }

    if (empty is not null)
    {
        DiagnosticsConfig.logger.LogInformation(eventId: 123, "Logout - empty is not null: " + empty);
        //DiagnosticsConfig.logger.LogInformation(eventId: 123, "Logout - empty type: " + typeof(empty));
        await signInManager.SignOutAsync();

        return Results.Ok();
    }

    return Results.Unauthorized();
}).RequireAuthorization();

app.UseHttpsRedirection();

app.MapGet("/roles", (ClaimsPrincipal user) =>
{
    if (user.Identity is not null && user.Identity.IsAuthenticated)
    {
        var identity = (ClaimsIdentity)user.Identity;
        var roles = identity.FindAll(identity.RoleClaimType)
            .Select(c =>
                new
                {
                    c.Issuer,
                    c.OriginalIssuer,
                    c.Type,
                    c.Value,
                    c.ValueType
                });

        return TypedResults.Json(roles);
    }

    return Results.Unauthorized();
}).RequireAuthorization();

app.MapPost("/data-processing-1", ([FromBody] FormModel model) =>
    Results.Text($"{model.Message.Length} characters"))
        .RequireAuthorization();

app.MapPost("/data-processing-2", ([FromBody] FormModel model) =>
    Results.Text($"{model.Message.Length} characters"))
        .RequireAuthorization(policy => policy.RequireRole("Manager"));

app.Run();

// Identity user
class AppUser : IdentityUser
{
    public IEnumerable<IdentityRole>? Roles { get; set; }
}

// Identity database
class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<AppUser>(options)
{
}

// Example form model
class FormModel
{
    public string Message { get; set; } = string.Empty;
}

public static class DiagnosticsConfig
{
    public const string ServiceName = "BlazorWebAssemblyStandaloneWithIdentityBackend";
    public static ActivitySource ActivitySource = new ActivitySource(ServiceName);

    public static Meter Meter = new(ServiceName);
    public static Counter<long> RequestCounter =
        Meter.CreateCounter<long>("app.request_counter");

    public static ILogger logger = LoggerFactory.Create(builder =>
        {
            builder.AddOpenTelemetry(options =>
            {
                //options.AddConsoleExporter();
                options.AddOtlpExporter();
                options.SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(
                    serviceName: ServiceName,
                    serviceVersion: "0.0.1"));
            });
        }).CreateLogger<Program>();
}
