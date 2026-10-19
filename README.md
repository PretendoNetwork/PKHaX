# PKHaX

### Legality check server for Pokemon Generation 6

PKHaX makes use of the [PKHeX](https://github.com/kwsch/PKHeX/) project for Pokémon legality checking.

## Building

Run `dotnet publish -c Release`. The binary will be built to `./bin/Release/net10.0/publish/PKHaX`

Example:
```
git clone https://github.com/PretendoNetwork/PKHaX
cd PKHaX
dotnet publish -c Release
```

## Configuration

All configuration options are handled via environment variables

`.env` files are supported

| Name                     | Description                                                                     | Required                |
|--------------------------|---------------------------------------------------------------------------------|-------------------------|
| `PKHAX_PRIVATE_KEY_PATH` | Path to your RSA 2048 private key PEM, used to sign legality check responses    | Yes                     |
| `PKHAX_PORT`             | Port for the validator server                                                   | No (Defaults to `9000`) |
| `PKHAX_CERTIFICATE_ID`   | Certificate ID the server expects clients to send, a number between 0 and 65535 | No (Defaults to `3`)    |
