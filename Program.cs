using dotenv.net;

namespace PKHaX {
	static class Program {
		public static void Main(string[] args) {
			DotEnv.Load(new DotEnvOptions(overwriteExistingVars: false));

			// TODO - It would be nice to display the current PKHeX version at startup

			Server.Start(args);
		}
	}
}
