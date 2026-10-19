using System.Security.Cryptography;

namespace PKHaX {
	static class Certificate {
		public static ushort EXPECTED_CERTIFICATE_ID = 3;

		public static byte[] rsaHeader = {
			0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
			0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00
		};

		public static RSA RSA_KEY_PAIR = RSA.Create();

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
	}
}
