using System.Text;
using System.Net;
using System.Security.Cryptography;
using PKHeX.Core;
using dotenv.net;
using System.Buffers;
using System.Buffers.Binary;
using System.Text.Json;

namespace PKHaX {
	class Server {
		public static HttpListener listener;

		public static string protocol = "http";
		public static int port = 9000;
		public static ushort EXPECTED_CERTIFICATE_ID = 3;
		public static byte[] rsaHeader = {
			0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
			0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00
		};

		public enum ValidatorV1ValidateResponseCode : byte {
			Legal = 0,
			Illegal = 1,
			InvalidCertificateID = 2
		}

		public enum ValidatorV1ValidatePayloadType : ushort {
			Unknown1 = 1, // * Seen in `DllGts.cro` and `DllRandomTrade.cro` (Wonder Trades)
			Unknown2 = 2, // * Seen in `DllGts.cro`
			PSSTrade = 3,
			Battle = 4,
			BattleVideo = 5
		}

		public sealed class ValidatorV1ValidateRequest {
			public string ServiceToken { get; init; } = "";
			public ushort CertificateID { get; init; }
			public ValidatorV1ValidatePayloadType PayloadType { get; init; }
			public object Payload { get; init; } = null!;
		}

		public sealed class ValidatorV1ValidateExtendedPayload {
			public ushort Count { get; init; }
			public List<ValidatorV1ValidateExtendedPayloadEntry> Entries { get; init; } = new();
		}

		public sealed class ValidatorV1ValidateExtendedPayloadEntry {
			// TODO - Can PKHeX handle this "Unknown" section natively or no? Should we even bother separating this out, what is this, have we just been getting lucky this whole time?
			public byte[] Unknown { get; init; } = null!;
			public byte[] EncryptedPokemon { get; init; } = null!;
		}

		public sealed class ValidatorV1ValidatePayload {
			public ushort Count { get; init; }
			public List<byte[]> EncryptedPokemon { get; init; } = new();
		}

		public static RSA RSA_KEY_PAIR = RSA.Create();

		public static Dictionary<string, Dictionary<string, Func<HttpListenerRequest, byte[]>>> REQUEST_HANDLERS = new Dictionary<string, Dictionary<string, Func<HttpListenerRequest, byte[]>>>();

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

		public static ValidatorV1ValidateRequest ParseValidatorV1ValidateRequest(ReadOnlyMemory<byte> body) {
			var reader = new SequenceReader<byte>(new ReadOnlySequence<byte>(body));

			if (!reader.TryReadTo(out ReadOnlySequence<byte> serviceTokenBytes, 0)) {
				throw new InvalidDataException("Failed to read service token");
			}

			string serviceToken = Encoding.ASCII.GetString(serviceTokenBytes.ToArray());

			if (!reader.TryReadLittleEndian(out short certificateID)) {
				throw new InvalidDataException("Failed to read certificate ID");
			}

			if (!reader.TryReadBigEndian(out short payloadType)) {
				throw new InvalidDataException("Failed to read payload type");
			}

			// * It appears that every payload type besides type 1 uses the basic encrypted Pokemon container.
			// * Unsure why there's different payload types for this, maybe the real server changed the kind
			// * of checks done depending on the context?
			object payload = (ValidatorV1ValidatePayloadType)(ushort)payloadType switch{
				ValidatorV1ValidatePayloadType.Unknown1 => ParseValidatorV1ValidateExtendedPayload(ref reader),
				ValidatorV1ValidatePayloadType.Unknown2 => ParseValidatorV1ValidatePayload(ref reader),
				ValidatorV1ValidatePayloadType.PSSTrade => ParseValidatorV1ValidatePayload(ref reader),
				ValidatorV1ValidatePayloadType.Battle => ParseValidatorV1ValidatePayload(ref reader),
				ValidatorV1ValidatePayloadType.BattleVideo => ParseValidatorV1ValidatePayload(ref reader),
				_ => throw new InvalidDataException($"Unknown payload type {payloadType}")
			};

			if (reader.Remaining != 0) {
				Console.WriteLine($"WARN: Payload type {payloadType} has {reader.Remaining} remaining bytes unparsed");
			}

			return new ValidatorV1ValidateRequest {
				ServiceToken = serviceToken,
				CertificateID = (ushort)certificateID,
				PayloadType = (ValidatorV1ValidatePayloadType)(ushort)payloadType,
				Payload = payload
			};
		}

		public static ValidatorV1ValidateExtendedPayload ParseValidatorV1ValidateExtendedPayload(ref SequenceReader<byte> reader) {
			if (!reader.TryReadBigEndian(out short count)) {
				throw new InvalidDataException("Failed to read count");
			}

			var payload = new ValidatorV1ValidateExtendedPayload {
				Count = (ushort)count
			};

			// * The response parser seems to cap this at 12, so assuming the request is also capped
			if (payload.Count > 12) {
				throw new InvalidDataException("Count is more than 12");
			}

			for (int i = 0; i < payload.Count; i++) {
				if (!reader.TryReadExact(0xA0, out var unknown)) {
					throw new InvalidDataException("Failed to read unknown data");
				}

				if (!reader.TryReadExact(0xE8, out var pokemon)) {
					throw new InvalidDataException("Failed to read encrypted Pokemon data");
				}

				payload.Entries.Add(new ValidatorV1ValidateExtendedPayloadEntry {
					Unknown = unknown.ToArray(),
					EncryptedPokemon = pokemon.ToArray()
				});
			}

			return payload;
		}

		public static ValidatorV1ValidatePayload ParseValidatorV1ValidatePayload(ref SequenceReader<byte> reader) {
			if (!reader.TryReadBigEndian(out short count)) {
				throw new InvalidDataException("Failed to read count");
			}

			var payload = new ValidatorV1ValidatePayload {
				Count = (ushort)count
			};

			// * The response parser seems to cap this at 12, so assuming the request is also capped
			if (payload.Count > 12) {
				throw new InvalidDataException("Count is more than 12");
			}

			for (int i = 0; i < payload.Count; i++) {
				if (!reader.TryReadExact(0xE8, out var pokemon)) {
					throw new InvalidDataException("Failed to read encrypted Pokemon data");
				}

				payload.EncryptedPokemon.Add(pokemon.ToArray());
			}

			return payload;
		}

		// * Handles validating Pokemon data for legality
		public static byte[] ValidatorV1Validate(HttpListenerRequest req) {
			using var ms = new MemoryStream();
			req.InputStream.CopyTo(ms);

			var body = ms.GetBuffer().AsMemory(0, (int)ms.Length);
			ValidatorV1ValidateRequest request;

			try {
				request = ParseValidatorV1ValidateRequest(body);
			} catch (Exception exception) {
				Console.WriteLine($"WARN: Failed to parse ValidatorV1Validate request: {exception}");

				// * The real server seems to return HTML with the text "error" here, so I don't think this matters. Just need to bail, it's bad data anyway
				return CreateValidatorV1ValidateResponse(ValidatorV1ValidateResponseCode.Illegal);
			}

			// TODO - VERIFY SERVICE TOKEN

			if (request.CertificateID != EXPECTED_CERTIFICATE_ID) {
				// * This is expected to happen, since the game requests the certificate at the start of a save file
				// * and then never again unless the server tells it to. So people with existing saves will not have
				// * our certificate ID
				return CreateValidatorV1ValidateResponse(ValidatorV1ValidateResponseCode.InvalidCertificateID);
			}

			// * This name is a guess, game seems to loop over these values when checking if the response is legal or not
			List<uint> legalityResults = new List<uint>();
			bool hasInvalid = false;

			switch (request.Payload) {
				case ValidatorV1ValidateExtendedPayload payload:
					foreach (var entry in payload.Entries) {
						var encryptedPokemon = entry.EncryptedPokemon;
						PK6 pokemon = new PK6(encryptedPokemon.ToArray());
						LegalityAnalysis legalityAnalysis = new LegalityAnalysis(pokemon);

						if (!legalityAnalysis.Valid) {
							if (!legalityAnalysis.Parsed) {
								Console.WriteLine($"WARN: Invalid pokemon: Failed to parse");
							} else {
								Console.WriteLine($"WARN: Invalid pokemon: {JsonSerializer.Serialize(legalityAnalysis.Results)}");
							}

							hasInvalid = true;
							legalityResults.Add(ValidatorV1ValidateResponseCode.Illegal);
						} else {
							legalityResults.Add(ValidatorV1ValidateResponseCode.Legal);
						}
					}
					break;
				case ValidatorV1ValidatePayload payload:
					foreach (var encryptedPokemon in payload.EncryptedPokemon) {
						PK6 pokemon = new PK6(encryptedPokemon.ToArray());
						LegalityAnalysis legalityAnalysis = new LegalityAnalysis(pokemon);

						if (!legalityAnalysis.Valid) {
							if (!legalityAnalysis.Parsed) {
								Console.WriteLine($"WARN: Invalid pokemon: Failed to parse");
							} else {
								Console.WriteLine($"WARN: Invalid pokemon: {JsonSerializer.Serialize(legalityAnalysis.Results)}");
							}

							hasInvalid = true;
							legalityResults.Add(ValidatorV1ValidateResponseCode.Illegal);
						} else {
							legalityResults.Add(ValidatorV1ValidateResponseCode.Legal);
						}
					}
					break;
			}

			if (hasInvalid) {
				return CreateValidatorV1ValidateResponse(ValidatorV1ValidateResponseCode.Illegal, legalityResults);
			}

			HashAlgorithmName algorithm = HashAlgorithmName.SHA256;
			RSASignaturePadding padding = RSASignaturePadding.Pkcs1;

			// TODO - WE DON'T ACTUALLY KNOW WHAT DATA THIS SIGNATURE IS OVER! LEAVING IT LIKE THIS FOR NOW UNTIL WE FIND IT
			// * We have sigpatches for these signatures so this doesn't super matter
			byte[] signature = RSA_KEY_PAIR.SignData(body.ToArray(), algorithm, padding);

			return CreateValidatorV1ValidateResponse(ValidatorV1ValidateResponseCode.Legal, legalityResults, signature);
		}

		public static byte[] CreateValidatorV1ValidateResponse(ValidatorV1ValidateResponseCode responseCode, IReadOnlyList<uint>? legalityResults = null, byte[]? signature = null) {
			int responseLength = 1;
			int legalityResultsCount = legalityResults?.Count ?? 0;
			int offset = 0;

			// * This doesn't exist in the invalid certificate response
			if (legalityResultsCount != 0) {
				responseLength += 2;
				responseLength += legalityResultsCount * 4;
			}

			// * This doesn't exist in the invalid certificate or illegal Pokemon responses
			if (signature != null) {
				responseLength += signature.Length;
			}

			byte[] response = new byte[responseLength];

			response[offset++] = (byte)responseCode;

			if (legalityResults != null) {
				BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), (ushort)legalityResults.Count);
				offset += 2;

				foreach (uint value in legalityResults) {
					BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(offset, 4), value);
					offset += 4;
				}
			}

			if (signature != null) {
				signature.CopyTo(response, offset);
			}

			return response;
		}

		public static byte[] ValidatorV1PublicKey(HttpListenerRequest req) {
			// TODO - VERIFY SERVICE TOKEN

			// TODO - Is there a better way to do this? I'm new to C# 💀
			byte[] publicKeyBytes = RSA_KEY_PAIR.ExportRSAPublicKey();
			publicKeyBytes = rsaHeader.Concat(publicKeyBytes).ToArray(); // * Add the starting ASN.1 that the game expects and C# doesn't generate...

			string publicKeyBase64String = System.Convert.ToBase64String(publicKeyBytes);
			byte[] publicKeyBase64Bytes = Encoding.ASCII.GetBytes(publicKeyBase64String);

			byte[] responseData = new byte[2 + publicKeyBase64Bytes.Length];

			BinaryPrimitives.WriteUInt16LittleEndian(responseData.AsSpan(), EXPECTED_CERTIFICATE_ID);
			Array.Copy(publicKeyBase64Bytes, 0, responseData, 2, publicKeyBase64Bytes.Length);

			return responseData;
		}

		public static void ImportRSAKey() {
			string? privateKeyPath = System.Environment.GetEnvironmentVariable("PKHAX_PRIVATE_KEY_PATH");

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

		public static void CheckCertificateIDEnvironmentVariable() {
			string? customCertificateIDString = System.Environment.GetEnvironmentVariable("PKHAX_CERTIFICATE_ID");

			if (!String.IsNullOrEmpty(customCertificateIDString)) {
				if (!UInt16.TryParse(customCertificateIDString, out ushort certificateID)) {
					Console.WriteLine("Invalid certificate ID. Certificate IDs must be a number between 0 and 65535, got {0}", customCertificateIDString);
					Environment.Exit(1);
				}

				EXPECTED_CERTIFICATE_ID = certificateID;

				Console.WriteLine("Using certificate ID {0}", EXPECTED_CERTIFICATE_ID);
			} else {
				Console.WriteLine("No certificate ID set. Using default ID {0}", EXPECTED_CERTIFICATE_ID);
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
