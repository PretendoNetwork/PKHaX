using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;

namespace PKHaX {
	static class Server {
		public static string protocol = "http";

		public static void Start(string[] args) {
			WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(args);

			PKHaXOptions pkhaxOptions = PKHaXOptions.Read(builder.Configuration);

			builder.Services.AddSingleton(Options.Create(pkhaxOptions));
			builder.Services.AddSingleton<Certificate>();

			string prefix = string.Format("{0}://*:{1}/", protocol, pkhaxOptions.Port);

			builder.WebHost.UseUrls(prefix);
			builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);
			builder.Logging.SetMinimumLevel(LogLevel.Warning);

			WebApplication app = builder.Build();

			app.Services.GetRequiredService<Certificate>();

			app.Use(async (context, next) => {
				await next();

				Console.WriteLine($"{context.Request.Method} {context.Request.GetDisplayUrl()} - {context.Response.StatusCode}");
			});

			CreateRequestHandlers(app);

			Console.WriteLine("Server listening on {0}", prefix);

			app.Run();
		}

		public static void CreateRequestHandlers(WebApplication app) {
			app.MapPost("/validator/v1/validate", ValidatorV1Validate.HandleAsync);
			app.MapPost("/validator/v1/public_key", ValidatorV1PublicKey.HandleAsync);
		}

		// * Written out by hand rather than with Results.Bytes so that no Content-Type is set,
		// * matching the real servers
		public static async Task WriteResponse(HttpContext context, byte[] responseData) {
			context.Response.StatusCode = StatusCodes.Status200OK;
			context.Response.ContentLength = responseData.Length;

			await context.Response.Body.WriteAsync(responseData);
		}
	}
}
