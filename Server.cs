using Microsoft.AspNetCore.Http.Extensions;

namespace PKHaX {
	static class Server {
		public static string protocol = "http";
		public static int port = 9000;

		public static void Start(string[] args) {
			string prefix = string.Format("{0}://*:{1}/", protocol, port);

			WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(args);

			builder.WebHost.UseUrls(prefix);
			builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);
			builder.Logging.SetMinimumLevel(LogLevel.Warning);

			WebApplication app = builder.Build();

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

		public static void CheckPortEnvironmentVariable() {
			string? customPortString = System.Environment.GetEnvironmentVariable("PKHAX_PORT");

			if (!String.IsNullOrEmpty(customPortString)) {
				if (Int32.TryParse(customPortString, out int customPort)) {
					port = customPort;
				} else {
					Console.WriteLine("{0} is not a valid number. Using default port {1}", customPortString, port);
				}
			} else {
				Console.WriteLine("No port set. Using default port {0}", port);
			}
		}
	}
}
