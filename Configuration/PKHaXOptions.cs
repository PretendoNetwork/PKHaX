namespace PKHaX {
	public sealed class PKHaXOptions {
		public ushort Port { get; set; } = 9000;
		public ushort CertificateID { get; set; } = 3;
		public string PrivateKeyPath { get; set; } = "";

		public static PKHaXOptions Read(IConfiguration configuration) {
			PKHaXOptions options = new PKHaXOptions {
				PrivateKeyPath = configuration["PKHAX_PRIVATE_KEY_PATH"] ?? ""
			};

			options.ReadPort(configuration);
			options.ReadCertificateID(configuration);

			return options;
		}

		private void ReadPort(IConfiguration configuration) {
			string? customPortString = configuration["PKHAX_PORT"];

			if (!String.IsNullOrEmpty(customPortString)) {
				if (UInt16.TryParse(customPortString, out ushort customPort)) {
					Port = customPort;
				} else {
					Console.WriteLine("{0} is not a valid number. Using default port {1}", customPortString, Port);
				}
			} else {
				Console.WriteLine("No port set. Using default port {0}", Port);
			}
		}

		private void ReadCertificateID(IConfiguration configuration) {
			string? customCertificateIDString = configuration["PKHAX_CERTIFICATE_ID"];

			if (!String.IsNullOrEmpty(customCertificateIDString)) {
				if (!UInt16.TryParse(customCertificateIDString, out ushort certificateID)) {
					Console.WriteLine("Invalid certificate ID. Certificate IDs must be a number between 0 and 65535, got {0}", customCertificateIDString);
					Environment.Exit(1);
				}

				CertificateID = certificateID;

				Console.WriteLine("Using certificate ID {0}", CertificateID);
			} else {
				Console.WriteLine("No certificate ID set. Using default ID {0}", CertificateID);
			}
		}
	}
}
