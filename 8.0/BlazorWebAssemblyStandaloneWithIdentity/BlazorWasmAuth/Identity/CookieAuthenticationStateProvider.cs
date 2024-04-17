using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using BlazorWasmAuth.Identity.Models;
using System.Text;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Components;
using OpenTelemetry;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace BlazorWasmAuth.Identity
{
    /// <summary>
    /// Handles state for cookie-based auth.
    /// </summary>
    public class CookieAuthenticationStateProvider : AuthenticationStateProvider, IAccountManagement
    {
        /*public CookieAuthenticationStateProvider (ILogger<CookieAuthenticationStateProvider> logger)
        {
            _logger = logger;
        }*/

        /*[Inject]
        public ILogger<CookieAuthenticationStateProvider> Logger { get; set; }

        [Inject]
        public ILoggerFactory _Factory { get; set; }*/

        /// <summary>
        /// Map the JavaScript-formatted properties to C#-formatted classes.
        /// </summary>
        private readonly JsonSerializerOptions jsonSerializerOptions =
            new()
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            };

        /// <summary>
        /// Special auth client.
        /// </summary>
        private readonly HttpClient _httpClient;

        /// <summary>
        /// Authentication state.
        /// </summary>
        private bool _authenticated = false;

        /// <summary>
        /// Default principal for anonymous (not authenticated) users.
        /// </summary>
        private readonly ClaimsPrincipal Unauthenticated =
            new(new ClaimsIdentity());

        /// <summary>
        /// Create a new instance of the auth provider.
        /// </summary>
        /// <param name="httpClientFactory">Factory to retrieve auth client.</param>
        public CookieAuthenticationStateProvider(IHttpClientFactory httpClientFactory)
            => _httpClient = httpClientFactory.CreateClient("Auth");

        /// <summary>
        /// Register a new user.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <param name="password">The user's password.</param>
        /// <returns>The result serialized to a <see cref="FormResult"/>.
        /// </returns>
        public async Task<FormResult> RegisterAsync(string email, string password)
        {
            string[] defaultDetail = ["An unknown error prevented registration from succeeding."];

            try
            {
                // make the request
                var result = await _httpClient.PostAsJsonAsync(
                    "register", new
                    {
                        email,
                        password
                    });

                // successful?
                if (result.IsSuccessStatusCode)
                {
                    return new FormResult { Succeeded = true };
                }

                // body should contain details about why it failed
                var details = await result.Content.ReadAsStringAsync();
                var problemDetails = JsonDocument.Parse(details);
                var errors = new List<string>();
                var errorList = problemDetails.RootElement.GetProperty("errors");

                foreach (var errorEntry in errorList.EnumerateObject())
                {
                    if (errorEntry.Value.ValueKind == JsonValueKind.String)
                    {
                        errors.Add(errorEntry.Value.GetString()!);
                    }
                    else if (errorEntry.Value.ValueKind == JsonValueKind.Array)
                    {
                        errors.AddRange(
                            errorEntry.Value.EnumerateArray().Select(
                                e => e.GetString() ?? string.Empty)
                            .Where(e => !string.IsNullOrEmpty(e)));
                    }
                }

                // return the error list
                return new FormResult
                {
                    Succeeded = false,
                    ErrorList = problemDetails == null ? defaultDetail : [.. errors]
                };
            }
            catch { }

            // unknown error
            return new FormResult
            {
                Succeeded = false,
                ErrorList = defaultDetail
            };
        }

        private static readonly ActivitySource MyLibraryActivitySource = new(
                "MyCompany.MyProduct.MyLibrary");

        /// <summary>
        /// User login.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <param name="password">The user's password.</param>
        /// <returns>The result of the login request serialized to a <see cref="FormResult"/>.</returns>
        public async Task<FormResult> LoginAsync(string email, string password, ILogger Logger)
        {
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
                .ConfigureResource(resource => resource.AddService("MyServiceName"))
                .AddConsoleExporter()
                /*.AddOtlpExporter(options =>
    {
        options.Endpoint = new Uri("https://otlp.nr-data.net");
        options.Headers = "api-key=NEW_RELIC_LICENSE_KEY";
        options.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
    })*/
                .Build();

            // This activity source is enabled.
            using (var activity = MyLibraryActivitySource.StartActivity("SayHello"))
            {
                activity?.SetTag("foo", 1);
                activity?.SetTag("bar", "Hello, World!");
            }
            //using var myActivity = Telemetry.MyActivitySource.StartActivity("LoginAsync");
            //Telemetry.logger.LogInformation(eventId: 123, "LoginAsync start");

            //var logger = LoggerFactory.CreateLogger("CustomCategory");
            //var logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger<Program>();
            Logger.LogInformation("Someone has clicked me!");
            //_httpClient.All.SendAsync("Log", "test");

            //var loggerFromDI = _Factory.CreateLogger("Values"); 
            //var loggerFromDI = _Factory.CreateLogger<CookieAuthenticationStateProvider>();

            //_logger.LogDebug("From direct dependency injection");
            //loggerFromDI.LogDebug("From dependency injection factory");

            try
            {
                // login with cookies
                var result = await _httpClient.PostAsJsonAsync(
                    "login?useCookies=true", new
                    {
                        email,
                        password
                    });

                // success?
                if (result.IsSuccessStatusCode)
                {
                    // need to refresh auth state
                    NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());

                    //Telemetry.logger.LogInformation(eventId: 123, "LoginAsync done with success");

                    // success!
                    return new FormResult { Succeeded = true };
                }
            }
            catch { }

            //Telemetry.logger.LogInformation(eventId: 123, "LoginAsync done with error");
            tracerProvider.Dispose();

            // unknown error
            return new FormResult
            {
                Succeeded = false,
                ErrorList = ["Invalid email and/or password."]
            };
        }

        /// <summary>
        /// Get authentication state.
        /// </summary>
        /// <remarks>
        /// Called by Blazor anytime and authentication-based decision needs to be made, then cached
        /// until the changed state notification is raised.
        /// </remarks>
        /// <returns>The authentication state asynchronous request.</returns>
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            _authenticated = false;

            // default to not authenticated
            var user = Unauthenticated;

            try
            {
                // the user info endpoint is secured, so if the user isn't logged in this will fail
                var userResponse = await _httpClient.GetAsync("manage/info");

                // throw if user info wasn't retrieved
                userResponse.EnsureSuccessStatusCode();

                // user is authenticated,so let's build their authenticated identity
                var userJson = await userResponse.Content.ReadAsStringAsync();
                var userInfo = JsonSerializer.Deserialize<UserInfo>(userJson, jsonSerializerOptions);

                if (userInfo != null)
                {
                    // in our system name and email are the same
                    var claims = new List<Claim>
                    {
                        new(ClaimTypes.Name, userInfo.Email),
                        new(ClaimTypes.Email, userInfo.Email)
                    };

                    // add any additional claims
                    claims.AddRange(
                        userInfo.Claims.Where(c => c.Key != ClaimTypes.Name && c.Key != ClaimTypes.Email)
                            .Select(c => new Claim(c.Key, c.Value)));

                    // tap the roles endpoint for the user's roles
                    var rolesResponse = await _httpClient.GetAsync("roles");

                    // throw if request fails
                    rolesResponse.EnsureSuccessStatusCode();

                    // read the response into a string
                    var rolesJson = await rolesResponse.Content.ReadAsStringAsync();

                    // deserialize the roles string into an array
                    var roles = JsonSerializer.Deserialize<RoleClaim[]>(rolesJson, jsonSerializerOptions);

                    // if there are roles, add them to the claims collection
                    if (roles?.Length > 0)
                    {
                        foreach (var role in roles)
                        {
                            if (!string.IsNullOrEmpty(role.Type) && !string.IsNullOrEmpty(role.Value))
                            {
                                claims.Add(new Claim(role.Type, role.Value, role.ValueType, role.Issuer, role.OriginalIssuer));
                            }
                        }
                    }

                    // set the principal
                    var id = new ClaimsIdentity(claims, nameof(CookieAuthenticationStateProvider));
                    user = new ClaimsPrincipal(id);
                    _authenticated = true;
                }
            }
            catch { }

            // return the state
            return new AuthenticationState(user);
        }

        public async Task LogoutAsync()
        {
            const string Empty = "{}";
            var emptyContent = new StringContent(Empty, Encoding.UTF8, "application/json");
            await _httpClient.PostAsync("logout", emptyContent);
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        public async Task<bool> CheckAuthenticatedAsync()
        {
            await GetAuthenticationStateAsync();
            return _authenticated;
        }

        public class RoleClaim
        {
            public string? Issuer { get; set; }
            public string? OriginalIssuer { get; set; }
            public string? Type { get; set; }
            public string? Value { get; set; }
            public string? ValueType { get; set; }
        }

        /*public static class Telemetry
        {
            public const string ServiceName = "BlazorWebAssemblyStandaloneWithIdentityFrontend";

            // Name it after the service name for your app.
            // It can come from a config file, constants file, etc.
            public static readonly ActivitySource MyActivitySource = new(ServiceName);

            public static ILogger logger = LoggerFactory.Create(builder =>
            {
                builder.AddOpenTelemetry(options =>
                {
                    options.AddConsoleExporter();
                    //options.AddOtlpExporter();
                    options.SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(
                        serviceName: ServiceName,
                        serviceVersion: "0.0.1"));
                });
            }).CreateLogger<Program>();
        }*/
    }
}
