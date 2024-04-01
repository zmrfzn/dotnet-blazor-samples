using BlazorWebAppEFCore.Components;
using Microsoft.EntityFrameworkCore;
using BlazorWebAppEFCore.Data;
using BlazorWebAppEFCore.Grid;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using OpenTelemetry.Instrumentation.AspNetCore;
using System.Diagnostics.Metrics;
using System.Diagnostics;

var serviceName = "MyServiceName";
var serviceVersion = "1.0.0";

var appbuilder = WebApplication.CreateBuilder(args);

DiagnosticsConfig.logger.LogInformation(eventId: 123, "Getting started!");

// Add OpenTelemetry Traces and Metrics to our Service Collection
appbuilder.Services.AddOpenTelemetry()
    .WithTracing(tracerProviderBuilder =>
        tracerProviderBuilder
            .AddSource(DiagnosticsConfig.ActivitySource.Name)
            .ConfigureResource(resource => resource
                .AddService(DiagnosticsConfig.ServiceName))
            .AddAspNetCoreInstrumentation()
            //.AddConsoleExporter()
            .AddOtlpExporter()
        )
    .WithMetrics(metricsProviderBuilder =>
        metricsProviderBuilder
            .ConfigureResource(resource => resource
                .AddService(DiagnosticsConfig.ServiceName))
            .AddAspNetCoreInstrumentation()
            //.AddConsoleExporter()
            .AddMeter(DiagnosticsConfig.Meter.Name)
            .AddOtlpExporter()
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

appbuilder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Register factory and configure the options
#region snippet1
appbuilder.Services.AddDbContextFactory<ContactContext>(opt =>
    opt.UseSqlite($"Data Source={nameof(ContactContext.ContactsDb)}.db"));
#endregion

// Pager
appbuilder.Services.AddScoped<IPageHelper, PageHelper>();

// Filters
appbuilder.Services.AddScoped<IContactFilters, GridControls>();

// Query adapter (applies filter to contact request)
appbuilder.Services.AddScoped<GridQueryAdapter>();

// Service to communicate success on edit between pages
appbuilder.Services.AddScoped<EditSuccess>();

var app = appbuilder.Build();

// This section sets up and seeds the database. Seeding is NOT normally
// handled this way in production. The following approach is used in this
// sample app to make the sample simpler. The app can be cloned. The
// connection string is configured. The app can be run.
await using var scope = app.Services.GetRequiredService<IServiceScopeFactory>().CreateAsyncScope();
var options = scope.ServiceProvider.GetRequiredService<DbContextOptions<ContactContext>>();
await DatabaseUtility.EnsureDbCreatedAndSeedWithCountOfAsync(options, 500);

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

public static class DiagnosticsConfig
{
    public const string ServiceName = "BlazorWebAppEFCore";
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