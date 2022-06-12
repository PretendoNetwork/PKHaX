using System;
using System.IO;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using PKHeX.Core;

namespace PKHaX {
	class Server {
		public static HttpListener listener;
		
		public static string protocol = "http";
		public static int port = 9000;

		public static byte[] ILLEGAL_POKEMON_MAGIC = new byte[] { 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A };
		public static byte[] LEGAL_POKEMON_MAGIC = new byte[] { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };

		public static async Task HandleIncomingConnections() {
			while (true) {
				HttpListenerContext ctx = await listener.GetContextAsync();

				HttpListenerRequest req = ctx.Request;
				HttpListenerResponse resp = ctx.Response;

				resp.StatusCode = 404;

				if ((req.HttpMethod == "POST") && (req.Url.AbsolutePath == "/validator/v1/validate")) {
					MemoryStream ms = new MemoryStream();
					req.InputStream.CopyTo(ms);

					byte[] body = ms.ToArray();

					byte[] serviceToken = new byte[0x58];
					byte[] unknown = new byte[0xA7];
					byte[] encryptedPkm = new byte[0xE8];

					Array.Copy(body, 0, serviceToken, 0, 0x58);
					Array.Copy(body, 0x58, unknown, 0, 0xA7);
					Array.Copy(body, 0x58 + 0xA7, encryptedPkm, 0, 0xE8);

					var pkm = new PK6(encryptedPkm);
					var la = new LegalityAnalysis(pkm);

					byte[] responseData;

					if (la.Valid) {
						responseData = new byte[0x107];
						Array.Copy(LEGAL_POKEMON_MAGIC, 0, responseData, 0, LEGAL_POKEMON_MAGIC.Length);

						// Real server sends back an RSA-256 signature here
						// after the magic

						// We do not have the private key, and the public key
						// is requested one time when making a new save and
						// stored in the save file, making it risky to patch

						// Leaving signature as all null bytes for now
					} else {
						responseData = new byte[0x07];
						Array.Copy(ILLEGAL_POKEMON_MAGIC, 0, responseData, 0, ILLEGAL_POKEMON_MAGIC.Length);
					}

					resp.ContentLength64 = responseData.LongLength;
					resp.StatusCode = 200;

					await resp.OutputStream.WriteAsync(responseData, 0, responseData.Length);
				}

				resp.Close();
			}
		}

		public static void Main(string[] args) {
			string prefix = string.Format("{0}://*:{1}/", protocol, port);

			listener = new HttpListener();

			listener.Prefixes.Add(prefix);
			listener.Start();

			Console.WriteLine("Server listening on {0}", prefix);

			Task listenTask = HandleIncomingConnections();

			listenTask.GetAwaiter().GetResult();

			listener.Close();
		}
	}
}