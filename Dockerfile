FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build

WORKDIR /src

COPY PKHaX.csproj .

RUN dotnet restore "PKHaX.csproj"

COPY . .

ARG ARCHITECTURE=x64
RUN dotnet publish "PKHaX.csproj" -c Release -o /app/publish -r "linux-$ARCHITECTURE"

FROM debian:12
WORKDIR /app

ENV PKHAX_PORT=9000
ENV PKHAX_PRIVATE_KEY_PATH=/app/private.key
EXPOSE 9000

COPY --from=build /app/publish .

ENTRYPOINT ["./PKHaX"]
