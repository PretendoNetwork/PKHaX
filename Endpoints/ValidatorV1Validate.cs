using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using PKHeX.Core;

namespace PKHaX {
	// * Handles validating Pokemon data for legality
	static class ValidatorV1Validate {
		public static async Task HandleAsync(HttpContext context, Certificate certificate) {
			using var ms = new MemoryStream();
			await context.Request.Body.CopyToAsync(ms);

			byte[] responseData = Handle(ms.GetBuffer().AsMemory(0, (int)ms.Length), certificate);

			await Server.WriteResponse(context, responseData);
		}

		public static byte[] Handle(ReadOnlyMemory<byte> body, Certificate certificate) {
			ValidatorV1ValidateRequest request;

			try {
				request = ValidatorV1Parser.ParseRequest(body);
			} catch (Exception exception) {
				Console.WriteLine($"WARN: Failed to parse ValidatorV1Validate request: {exception}");

				// * The real server seems to return HTML with the text "error" here, so I don't think this matters. Just need to bail, it's bad data anyway
				return CreateResponse(ValidatorV1ValidateResponseCode.Illegal);
			}

			// TODO - VERIFY SERVICE TOKEN

			if (request.CertificateID != certificate.EXPECTED_CERTIFICATE_ID) {
				// * This is expected to happen, since the game requests the certificate at the start of a save file
				// * and then never again unless the server tells it to. So people with existing saves will not have
				// * our certificate ID
				return CreateResponse(ValidatorV1ValidateResponseCode.InvalidCertificateID);
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
							legalityResults.Add((uint)ValidatorV1ValidateResponseCode.Illegal);
						} else {
							legalityResults.Add((uint)ValidatorV1ValidateResponseCode.Legal);
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
							legalityResults.Add((uint)ValidatorV1ValidateResponseCode.Illegal);
						} else {
							legalityResults.Add((uint)ValidatorV1ValidateResponseCode.Legal);
						}
					}
					break;
			}

			if (hasInvalid) {
				return CreateResponse(ValidatorV1ValidateResponseCode.Illegal, legalityResults);
			}

			HashAlgorithmName algorithm = HashAlgorithmName.SHA256;
			RSASignaturePadding padding = RSASignaturePadding.Pkcs1;

			byte[] signature = certificate.RSA_KEY_PAIR.SignData(body.Slice(request.PayloadOffset).ToArray(), algorithm, padding);

			return CreateResponse(ValidatorV1ValidateResponseCode.Legal, legalityResults, signature);
		}

		public static byte[] CreateResponse(ValidatorV1ValidateResponseCode responseCode, IReadOnlyList<uint>? legalityResults = null, byte[]? signature = null) {
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
	}
}
