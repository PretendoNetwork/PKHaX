# PKHaX
### Legality check server for Pokemon Generation 6

PKHaX makes use of the [PKHeX](https://github.com/kwsch/PKHeX/) project for legality checking

## Building

Replace `ubuntu.21.04-x64` with your system

Binary will be built to `./bin/Release/net6.0/ubuntu.21.04-x64/publish/PKHaX`

```
git clone https://github.com/PretendoNetwork/PKHaX
cd PKHaX
dotnet publish -c Release -r ubuntu.21.04-x64
```