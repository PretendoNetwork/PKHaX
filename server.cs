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

		// TODO - Give these values proper names when more context is found
		public enum ValidatorV1ValidatePayloadType : ushort {
			Type1 = 1, // * Seems to be nearly identical to Type2, but has an extra 0xA0 blob before the Pokemon data?
			Type2 = 2
		}

		public sealed class ValidatorV1ValidateRequest {
			public string ServiceToken { get; init; } = "";
			public ushort CertificateID { get; init; }
			public ValidatorV1ValidatePayloadType PayloadType { get; init; }
			public object Payload { get; init; } = null!;
		}

		// TODO - Give these structs proper names when more context is found
		public sealed class ValidatorV1ValidateType1Payload {
			public ushort Count { get; init; }
			public List<ValidatorV1ValidateType1Entry> Entries { get; init; } = new();
		}

		public sealed class ValidatorV1ValidateType1Entry {
			// TODO - Can PKHeX handle this "Unknown" section natively or no? Should we even bother separating this out, what is this, have we just been getting lucky this whole time?
			public byte[] Unknown { get; init; } = null!;
			public byte[] EncryptedPokemon { get; init; } = null!;
		}

		public sealed class ValidatorV1ValidateType2Payload {
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

			object payload = (ValidatorV1ValidatePayloadType)(ushort)payloadType switch{
				ValidatorV1ValidatePayloadType.Type1 => ParseValidatorV1ValidateType1Payload(ref reader),
				ValidatorV1ValidatePayloadType.Type2 => ParseValidatorV1ValidateType2Payload(ref reader),
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

		public static ValidatorV1ValidateType1Payload ParseValidatorV1ValidateType1Payload(ref SequenceReader<byte> reader) {
			if (!reader.TryReadBigEndian(out short count)) {
				throw new InvalidDataException("Failed to read count");
			}

			var payload = new ValidatorV1ValidateType1Payload {
				Count = (ushort)count
			};

			for (int i = 0; i < payload.Count; i++) {
				if (!reader.TryReadExact(0xA0, out var unknown)) {
					throw new InvalidDataException("Failed to read unknown data");
				}

				if (!reader.TryReadExact(0xE8, out var pokemon)) {
					throw new InvalidDataException("Failed to read encrypted Pokemon data");
				}

				payload.Entries.Add(new ValidatorV1ValidateType1Entry {
					Unknown = unknown.ToArray(),
					EncryptedPokemon = pokemon.ToArray()
				});
			}

			return payload;
		}

		public static ValidatorV1ValidateType2Payload ParseValidatorV1ValidateType2Payload(ref SequenceReader<byte> reader) {
			if (!reader.TryReadBigEndian(out short count)) {
				throw new InvalidDataException("Failed to read count");
			}

			var payload = new ValidatorV1ValidateType2Payload {
				Count = (ushort)count
			};

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
			ValidatorV1ValidateRequest request = ParseValidatorV1ValidateRequest(body);

			// TODO - VERIFY SERVICE TOKEN

			if (request.CertificateID != EXPECTED_CERTIFICATE_ID) {
				// * This is expected to happen, since the game requests the certificate at the start of a save file
				// * and then never again unless the server tells it to. So people with existing saves will not have
				// * our certificate ID
				return CreateValidatorV1ValidateResponse(ValidatorV1ValidateResponseCode.InvalidCertificateID);
			}

			// TODO - Figure out what these values mean and enum them, magic numbers bad
			List<uint> values = new List<uint>();
			bool hasInvalid = false;

			switch (request.Payload) {
				case ValidatorV1ValidateType1Payload payload:
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
							values.Add(0x0A); // * This came from a dump I believe, but the game seems to override this with a value of 1?
						} else {
							values.Add(0x00);
						}
					}
					break;
				case ValidatorV1ValidateType2Payload payload:
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
							values.Add(0x0A); // * This came from a dump I believe, but the game seems to override this with a value of 1?
						} else {
							values.Add(0x00);
						}
					}
					break;
			}

			if (hasInvalid) {
				return CreateValidatorV1ValidateResponse(ValidatorV1ValidateResponseCode.Illegal, values);
			}

			HashAlgorithmName algorithm = HashAlgorithmName.SHA256;
			RSASignaturePadding padding = RSASignaturePadding.Pkcs1;

			// TODO - WE DON'T ACTUALLY KNOW WHAT DATA THIS SIGNATURE IS OVER! LEAVING IT LIKE THIS FOR NOW UNTIL WE FIND IT
			// * We have sigpatches for these signatures so this doesn't super matter
			byte[] signature = RSA_KEY_PAIR.SignData(body.ToArray(), algorithm, padding);

			return CreateValidatorV1ValidateResponse(ValidatorV1ValidateResponseCode.Legal, values, signature);
		}

		public static byte[] CreateValidatorV1ValidateResponse(ValidatorV1ValidateResponseCode responseCode, IReadOnlyList<uint>? values = null, byte[]? signature = null) {
			int responseLength = 1;
			int valueCount = values?.Count ?? 0;
			int offset = 0;

			// * This doesn't exist in the invalid certificate response
			if (valueCount != 0) {
				responseLength += 2;
				responseLength += valueCount * 4;
			}

			// * This doesn't exist in the invalid certificate or illegal Pokemon responses
			if (signature != null) {
				responseLength += signature.Length;
			}

			byte[] response = new byte[responseLength];

			response[offset++] = (byte)responseCode;

			if (values != null) {
				BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), (ushort)values.Count);
				offset += 2;

				foreach (uint value in values) {
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
