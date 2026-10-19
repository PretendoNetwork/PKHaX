namespace PKHaX {
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
		public int PayloadOffset { get; init; }
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
}
