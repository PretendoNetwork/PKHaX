using System.Net;

namespace PKHaX {
	static class Server {
		public static HttpListener listener = new HttpListener();

		public static string protocol = "http";
		public static int port = 9000;

		public static Dictionary<string, Dictionary<string, Func<HttpListenerRequest, byte[]>>> REQUEST_HANDLERS = new Dictionary<string, Dictionary<string, Func<HttpListenerRequest, byte[]>>>();

		public static void Start() {
			string prefix = string.Format("{0}://*:{1}/", protocol, port);

			listener.Prefixes.Add(prefix);
			listener.Start();

			Console.WriteLine("Server listening on {0}", prefix);

			Task listenTask = HandleIncomingConnections();

			listenTask.GetAwaiter().GetResult();

			listener.Close();
		}

		public static async Task HandleIncomingConnections() {
			while (true) {
				try
				{
					HttpListenerContext ctx = await listener.GetContextAsync();

					HttpListenerRequest request = ctx.Request;
					HttpListenerResponse response = ctx.Response;

					response.StatusCode = 404;

					if (REQUEST_HANDLERS.ContainsKey(request.HttpMethod)) {
						Dictionary<string, Func<HttpListenerRequest, byte[]>> methodHandlers = REQUEST_HANDLERS[request.HttpMethod];

						if (request.Url != null && methodHandlers.ContainsKey(request.Url.AbsolutePath)) {
							Func<HttpListenerRequest, byte[]> handler = methodHandlers[request.Url.AbsolutePath];
							byte [] responseData = handler(request);

							response.ContentLength64 = responseData.LongLength;
							response.StatusCode = 200;

							await response.OutputStream.WriteAsync(responseData, 0, responseData.Length);
						}
					}
					Console.WriteLine($"{request.HttpMethod} {request.Url} - {response.StatusCode}");

					response.Close();
				}
				catch (Exception e)
				{
					Console.WriteLine($"Exception occured while writing response: {e}");
				}
			}
		}

		public static void CreateRequestHandlers() {
			Dictionary<string, Func<HttpListenerRequest, byte[]>> POSTHandlers = new Dictionary<string, Func<HttpListenerRequest, byte[]>>();

			POSTHandlers.Add("/validator/v1/validate", ValidatorV1Validate.Handle);
			POSTHandlers.Add("/validator/v1/public_key", ValidatorV1PublicKey.Handle);

			REQUEST_HANDLERS.Add("POST", POSTHandlers);
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
