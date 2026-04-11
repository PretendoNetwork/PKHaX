FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build

WORKDIR /src

COPY PKHaX.csproj .

RUN dotnet restore "PKHaX.csproj"

COPY . .

RUN dotnet publish "PKHaX.csproj" -c Release -o /app/publish

FROM alpine:3.23.3
WORKDIR /app

ENV PKHAX_PORT=9000
ENV PKHAX_PRIVATE_KEY_PATH=/app/private.key
EXPOSE 9000

RUN apk add --no-cache icu-dev openssl-dev

COPY --from=build /app/publish .

ENTRYPOINT ["./PKHaX"]
