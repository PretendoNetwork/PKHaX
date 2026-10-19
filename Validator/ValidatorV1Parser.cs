using System.Buffers;
using System.Text;

namespace PKHaX {
	static class ValidatorV1Parser {
		public static ValidatorV1ValidateRequest ParseRequest(ReadOnlyMemory<byte> body) {
			var reader = new SequenceReader<byte>(new ReadOnlySequence<byte>(body));

			if (!reader.TryReadTo(out ReadOnlySequence<byte> serviceTokenBytes, 0)) {
				throw new InvalidDataException("Failed to read service token");
			}

			string serviceToken = Encoding.ASCII.GetString(serviceTokenBytes.ToArray());

			// * Start of the encrypted Pokemon team payload. The response signature is over this section
			int payloadOffset = (int)serviceTokenBytes.Length + 1 + 6;

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
				ValidatorV1ValidatePayloadType.Unknown1 => ParseExtendedPayload(ref reader),
				ValidatorV1ValidatePayloadType.Unknown2 => ParsePayload(ref reader),
				ValidatorV1ValidatePayloadType.PSSTrade => ParsePayload(ref reader),
				ValidatorV1ValidatePayloadType.Battle => ParsePayload(ref reader),
				ValidatorV1ValidatePayloadType.BattleVideo => ParsePayload(ref reader),
				_ => throw new InvalidDataException($"Unknown payload type {payloadType}")
			};

			if (reader.Remaining != 0) {
				Console.WriteLine($"WARN: Payload type {payloadType} has {reader.Remaining} remaining bytes unparsed");
			}

			return new ValidatorV1ValidateRequest {
				ServiceToken = serviceToken,
				CertificateID = (ushort)certificateID,
				PayloadType = (ValidatorV1ValidatePayloadType)(ushort)payloadType,
				Payload = payload,
				PayloadOffset = payloadOffset
			};
		}

		public static ValidatorV1ValidateExtendedPayload ParseExtendedPayload(ref SequenceReader<byte> reader) {
			if (!reader.TryReadBigEndian(out short count)) {
				throw new InvalidDataException("Failed to read count");
			}

			var payload = new ValidatorV1ValidateExtendedPayload {
				Count = (ushort)count
			};

			// * A request with nothing in it to check is nonsense, bail
			if (payload.Count == 0) {
				throw new InvalidDataException("Count is 0");
			}

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

		public static ValidatorV1ValidatePayload ParsePayload(ref SequenceReader<byte> reader) {
			if (!reader.TryReadBigEndian(out short count)) {
				throw new InvalidDataException("Failed to read count");
			}

			var payload = new ValidatorV1ValidatePayload {
				Count = (ushort)count
			};

			// * A request with nothing in it to check is nonsense, bail
			if (payload.Count == 0) {
				throw new InvalidDataException("Count is 0");
			}

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
	}
}
