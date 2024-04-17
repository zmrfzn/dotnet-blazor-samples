using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using BlazorWasmAuth.Components;
using BlazorWasmAuth.Identity;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using System.Diagnostics.Metrics;
using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

// OpemTelemetry init (start)
// Step 1: Bind options to config using the name parameter.
/*builder.Services.Configure<OtlpExporterOptions>("tracing", builder.Configuration.GetSection("OpenTelemetry:tracing:otlp"));
builder.Services.Configure<OtlpExporterOptions>("metrics", builder.Configuration.GetSection("OpenTelemetry:metrics:otlp"));
builder.Services.Configure<OtlpExporterOptions>("logging", builder.Configuration.GetSection("OpenTelemetry:logging:otlp"));
*/

DiagnosticsConfig.logger.LogInformation(eventId: 123, "Getting started!");

// Add OpenTelemetry Traces and Metrics to our Service Collection
builder.Services.AddOpenTelemetry()
    .WithTracing(tracerProviderBuilder =>
        tracerProviderBuilder
            .AddSource(DiagnosticsConfig.ActivitySource.Name)
            .ConfigureResource(resource => resource
                .AddService(DiagnosticsConfig.ServiceName))
            //.AddAspNetCoreInstrumentation()
            //.AddConsoleExporter()
            .AddOtlpExporter(options =>
    {
        options.Endpoint = new Uri("https://otlp.nr-data.net");
        options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
        options.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
    })
        )
    .WithMetrics(metricsProviderBuilder =>
        metricsProviderBuilder
            .ConfigureResource(resource => resource
                .AddService(DiagnosticsConfig.ServiceName))
            //.AddAspNetCoreInstrumentation()
            //.AddConsoleExporter()
            .AddMeter(DiagnosticsConfig.Meter.Name)
            .AddMeter("System.Net.Http")
            .AddMeter("Microsoft.AspNetCore.Hosting")
            .AddMeter("Microsoft.AspNetCore.Server.Kestrel")
            .AddOtlpExporter(options =>
    {
        options.Endpoint = new Uri("https://otlp.nr-data.net");
        options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
        options.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
    })
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
// OpemTelemetry init (end)

//builder.Logging.SetMinimumLevel(LogLevel.Debug);
//builder.Services.AddSingleton<DiagnosticsConfig.logger>();
/*builder.Services.AddScoped(
    sp => (ILogger)sp.GetRequiredService<DiagnosticsConfig.logger>());*/
string ServiceName = "BlazorWebAssemblyStandaloneWithIdentityFrontend";
builder.Services.AddLogging(builder =>
{
    builder.AddOpenTelemetry(options =>
    {
        options.AddConsoleExporter();
        /*options.AddOtlpExporter(
    options =>
    {
        options.Endpoint = new Uri("https://otlp.nr-data.net");
        options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
        options.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
    });*/
        options.SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(
            serviceName: ServiceName,
            serviceVersion: "0.0.1"));
    });
}
            );
/*builder.Services.AddLogging(builder => builder
                .SetMinimumLevel(LogLevel.Debug)
                .AddFilter("Microsoft", LogLevel.Debug)
                .AddFilter("System", LogLevel.Debug)
                .AddOpenTelemetry(builder => builder.AddOtlpExporter(
    options =>
    {*/
//options.AddConsoleExporter();
//options.AddOtlpExporter();
/*options.SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(
    serviceName: ServiceName,
    serviceVersion: "0.0.1"));*/
/*options.Endpoint = new Uri("https://otlp.nr-data.net");
options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
}
              )));*/
/*builder.Logging.AddOpenTelemetry(builder => builder.AddOtlpExporter(
    options =>
    {
        //options.AddConsoleExporter();
        //options.AddOtlpExporter();
        /*options.SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(
            serviceName: ServiceName,
            serviceVersion: "0.0.1"));*/
/*    options.Endpoint = new Uri("https://otlp.nr-data.net");
    options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
}*/
/*    "logging",
    options =>
    {
        // Note: Options can also be set via code but order is important. In the example here the code will apply after configuration.
        options.Endpoint = new Uri("https://otlp.nr-data.net");
        options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
    }*/
//));

//builder.Services.AddTransient<DiagnosticsConfig>();
//builder.Services.AddSingleton(typeof(ILogger), DiagnosticsConfig.logger);
/*builder.Services.AddTransient(provider =>
{
    var loggerFactory = provider.GetRequiredService<ILoggerFactory>();
    const string categoryName = "Any";
    return loggerFactory.CreateLogger(categoryName);
});*/
DiagnosticsConfig.logger.LogInformation(eventId: 123, "Done with Otel config ...");

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// register the cookie handler
builder.Services.AddTransient<CookieHandler>();

// set up authorization
builder.Services.AddAuthorizationCore();

// register the custom state provider
builder.Services.AddScoped<AuthenticationStateProvider, CookieAuthenticationStateProvider>();

// register the account management interface
builder.Services.AddScoped(
    sp => (IAccountManagement)sp.GetRequiredService<AuthenticationStateProvider>());

// set base address for default host
builder.Services.AddScoped(sp =>
    new HttpClient { BaseAddress = new Uri(builder.Configuration["FrontendUrl"] ?? "https://localhost:5002") });

// configure client for auth interactions
builder.Services.AddHttpClient(
    "Auth",
    opt => opt.BaseAddress = new Uri(builder.Configuration["BackendUrl"] ?? "https://localhost:5001"))
    .AddHttpMessageHandler<CookieHandler>();

await builder.Build().RunAsync();

public static class DiagnosticsConfig
{
    public const string ServiceName = "BlazorWebAssemblyStandaloneWithIdentityFrontend";
    public static ActivitySource ActivitySource = new ActivitySource(ServiceName);

    public static Meter Meter = new(ServiceName);
    //public static Counter<long> RequestCounter =
    //    Meter.CreateCounter<long>("app.request_counter");

    //public static ILogger logger = LoggerFactory.Cre.CreateLogger("CustomCategory");
    public static ILogger logger = LoggerFactory.Create(builder =>
        {
            builder.AddOpenTelemetry(options =>
            {
                options.AddConsoleExporter();
                //&options.AddOtlpExporter();
                /*options.AddOtlpExporter(
                    "logging",
                    options =>
                    {
                        // Note: Options can also be set via code but order is important. In the example here the code will apply after configuration.
                        options.Endpoint = new Uri("https://otlp.nr-data.net");
                        options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
                    });*/
                options.SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(
                    serviceName: ServiceName,
                    serviceVersion: "0.0.1"));
            });
        }).CreateLogger<Program>();
}
