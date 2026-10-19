using System.Buffers.Binary;
using System.Text;

namespace PKHaX {
	static class ValidatorV1PublicKey {
		public static async Task HandleAsync(HttpContext context, Certificate certificate) {
			await Server.WriteResponse(context, Handle(certificate));
		}

		public static byte[] Handle(Certificate certificate) {
			// TODO - VERIFY SERVICE TOKEN

			// TODO - Is there a better way to do this? I'm new to C# 💀
			byte[] publicKeyBytes = certificate.RSA_KEY_PAIR.ExportRSAPublicKey();
			publicKeyBytes = Certificate.rsaHeader.Concat(publicKeyBytes).ToArray(); // * Add the starting ASN.1 that the game expects and C# doesn't generate...

			string publicKeyBase64String = System.Convert.ToBase64String(publicKeyBytes);
			byte[] publicKeyBase64Bytes = Encoding.ASCII.GetBytes(publicKeyBase64String);

			byte[] responseData = new byte[2 + publicKeyBase64Bytes.Length];

			BinaryPrimitives.WriteUInt16LittleEndian(responseData.AsSpan(), certificate.EXPECTED_CERTIFICATE_ID);
			Array.Copy(publicKeyBase64Bytes, 0, responseData, 2, publicKeyBase64Bytes.Length);

			return responseData;
		}
	}
}
