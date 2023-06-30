using System;
using System.IO;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Collections.Generic;
using PKHeX.Core;
using dotenv.net;

namespace PKHaX {
	class Server {
		public static HttpListener listener;

		public static string protocol = "http";
		public static int port = 9000;
		public static byte[] EXPECTED_CERTIFICATE_ID = new byte[] { 0xFF, 0xFF };
		public static byte[] INVALID_CERTIFICATE_ID_RESPONSE = new byte[] { 0x02 };
		public static byte[] ILLEGAL_POKEMON_RESPONSE = new byte[] { 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A };
		public static byte[] LEGAL_POKEMON_MAGIC = new byte[] { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
		public static RSA RSA_KEY_PAIR = RSA.Create();

		public static Dictionary<string, Dictionary<string, Func<HttpListenerRequest, byte[]>>> REQUEST_HANDLERS = new Dictionary<string, Dictionary<string, Func<HttpListenerRequest, byte[]>>>();

		public static async Task HandleIncomingConnections() {
			while (true) {
				HttpListenerContext ctx = await listener.GetContextAsync();

				HttpListenerRequest request = ctx.Request;
				HttpListenerResponse response = ctx.Response;

				response.StatusCode = 404;

				if (REQUEST_HANDLERS.ContainsKey(request.HttpMethod)) {
					Dictionary<string, Func<HttpListenerRequest, byte[]>> methodHandlers = REQUEST_HANDLERS[request.HttpMethod];

					if (methodHandlers.ContainsKey(request.Url.AbsolutePath)) {
						Func<HttpListenerRequest, byte[]> handler = methodHandlers[request.Url.AbsolutePath];
						byte [] responseData = handler(request);

						response.ContentLength64 = responseData.LongLength;
						response.StatusCode = 200;

						await response.OutputStream.WriteAsync(responseData, 0, responseData.Length);
					}
				}

				response.Close();
			}
		}

		public static byte[] ValidatorV1Validate(HttpListenerRequest req) {
			MemoryStream ms = new MemoryStream();
			req.InputStream.CopyTo(ms);

			byte[] body = ms.ToArray();

			byte[] serviceToken = new byte[0x58];
			byte[] unknown = new byte[0xA7];
			byte[] encryptedPokemon = new byte[0xE8];

			int serviceTokenOffset = 0;
			int unknownOffset = serviceTokenOffset + serviceToken.Length;
			int encryptedPokemonOffset = unknownOffset + unknown.Length;

			Array.Copy(body, serviceTokenOffset, serviceToken, 0, serviceToken.Length);
			Array.Copy(body, unknownOffset, unknown, 0, unknown.Length);
			Array.Copy(body, encryptedPokemonOffset, encryptedPokemon, 0, encryptedPokemon.Length);

			// TODO - VERIFY SERVICE TOKEN

			byte[] certificateID = new byte[0x2];

			Array.Copy(unknown, 0, certificateID, 0, certificateID.Length);

			if (!certificateID.SequenceEqual(EXPECTED_CERTIFICATE_ID)) {
				return INVALID_CERTIFICATE_ID_RESPONSE;
			}

			PK6 pokemon = new PK6(encryptedPokemon);
			LegalityAnalysis legalityAnalysis = new LegalityAnalysis(pokemon);

			if (!legalityAnalysis.Valid) {
				return ILLEGAL_POKEMON_RESPONSE;
			}

			HashAlgorithmName algorithm = HashAlgorithmName.SHA256;
			RSASignaturePadding padding = RSASignaturePadding.Pkcs1;

			// * WE DON'T ACTUALLY KNOW WHAT DATA THIS SIGNATURE IS OVER!
			// * LEAVING IT LIKE THIS FOR NOW UNTIL WE FIND IT
			byte[] signature = RSA_KEY_PAIR.SignData(encryptedPokemon, 0, encryptedPokemon.Length, algorithm, padding);
			byte[] responseData = new byte[LEGAL_POKEMON_MAGIC.Length + signature.Length];

			Array.Copy(LEGAL_POKEMON_MAGIC, 0, responseData, 0, LEGAL_POKEMON_MAGIC.Length);
			Array.Copy(signature, 0, responseData, LEGAL_POKEMON_MAGIC.Length, signature.Length);

			return responseData;
		}

		public static byte[] ValidatorV1PublicKey(HttpListenerRequest req) {
			// TODO - VERIFY SERVICE TOKEN

			// TODO - Is there a better way to do this? I'm new to c# 💀
			byte[] publicKeyBytes = RSA_KEY_PAIR.ExportRSAPublicKey();
			string publicKeyBase64String = System.Convert.ToBase64String(publicKeyBytes);
			byte[] publicKeyBase64Bytes = Encoding.ASCII.GetBytes(publicKeyBase64String);

			byte[] responseData = new byte[EXPECTED_CERTIFICATE_ID.Length + publicKeyBase64Bytes.Length];

			Array.Copy(EXPECTED_CERTIFICATE_ID, 0, responseData, 0, EXPECTED_CERTIFICATE_ID.Length);
			Array.Copy(publicKeyBase64Bytes, 0, responseData, EXPECTED_CERTIFICATE_ID.Length, publicKeyBase64Bytes.Length);

			return responseData;
		}

		public static void ImportRSAKey() {
			string privateKeyPath = System.Environment.GetEnvironmentVariable("PKHAX_PRIVATE_KEY_PATH");

			if (String.IsNullOrEmpty(privateKeyPath)) {
				Console.WriteLine("PKHAX_PRIVATE_KEY_PATH is not set. Set PKHAX_PRIVATE_KEY_PATH to the path of your RSA 2048 private key PEM");
				System.Environment.Exit(1);
			}

			if (!File.Exists(privateKeyPath)) {
				Console.WriteLine("File {0} does not exist. Set PKHAX_PRIVATE_KEY_PATH to the path of your RSA 2048 private key PEM", privateKeyPath);
				System.Environment.Exit(1);
			}

			try {
				string privateKeyText = File.ReadAllText(privateKeyPath);

				RSA_KEY_PAIR.ImportFromPem(privateKeyText);
			} catch (System.Exception) {
				Console.WriteLine("Invalid RSA private key PEM");
				throw;
			}

			// * RSA keys can only be 2048
			if (RSA_KEY_PAIR.KeySize != 2048) {
				Console.WriteLine("Invalid RSA key size. Expected 2048, got {0}", RSA_KEY_PAIR.KeySize);
				System.Environment.Exit(1);
			}

			// * Dirty check to see if the key pair really contains a private key
			// TODO - Better way to do this?
			try {
				RSA_KEY_PAIR.ExportRSAPrivateKey();
			} catch (System.Exception) {
				Console.WriteLine("RSA key provided is not a private key. Please provide an RSA 2048 private key");
				throw;
			}
		}

		public static void CreateRequestHandlers() {
			Dictionary<string, Func<HttpListenerRequest, byte[]>> POSTHandlers = new Dictionary<string, Func<HttpListenerRequest, byte[]>>();

			POSTHandlers.Add("/validator/v1/validate", ValidatorV1Validate);
			POSTHandlers.Add("/validator/v1/public_key", ValidatorV1PublicKey);

			REQUEST_HANDLERS.Add("POST", POSTHandlers);
		}

		public static void CheckEnvironmentVariables() {
			CheckPortEnvironmentVariable();
			CheckCertificateIDEnvironmentVariable();
		}

		public static void CheckPortEnvironmentVariable() {
			string customPortString = System.Environment.GetEnvironmentVariable("PKHAX_PORT");

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

		public static void CheckCertificateIDEnvironmentVariable() {
			string customCertificateIDString = System.Environment.GetEnvironmentVariable("PKHAX_CERTIFICATE_ID");

			if (!String.IsNullOrEmpty(customCertificateIDString)) {
				int hexLength = customCertificateIDString.Length;

				if (hexLength != 4) {
					Console.WriteLine("Invalid certificate ID. Certificate IDs must be set as exactly 2 bytes represented as 4 hex characters (ex, ABCD), got {0}", customCertificateIDString);
					System.Environment.Exit(1);
				}

				byte[] bytes = new byte[hexLength / 2];
				for (int i = 0; i < hexLength; i += 2) {
					string chunk = customCertificateIDString.Substring(i, 2);

					try {
						bytes[i / 2] = Convert.ToByte(chunk, 16);
					} catch (System.Exception) {
						Console.WriteLine("Invalid certificate ID. Chunk {0} is not valid hex. Certificate IDs must be set as exactly 2 bytes represented as 4 hex characters (ex, ABCD)", chunk);
						System.Environment.Exit(1);
					}
				}

				EXPECTED_CERTIFICATE_ID = bytes;

				Console.WriteLine("Using certificate ID {0}", Convert.ToHexString(bytes));
			} else {
				Console.WriteLine("No certificate ID set. Using default ID {0}", Convert.ToHexString(EXPECTED_CERTIFICATE_ID));
			}
		}

		public static void Main(string[] args) {
			DotEnv.Load();

			ImportRSAKey();
			CreateRequestHandlers();
			CheckEnvironmentVariables();

			// TODO - It would be nice to display the current PKHeX version at startup

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
