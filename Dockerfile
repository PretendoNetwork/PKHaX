FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build

WORKDIR /src

COPY PKHaX.csproj .

RUN dotnet restore "PKHaX.csproj"

COPY . .

# This if logic is done to set the correct architecture for the runtime, dotnet publish needs x64 wheras Docker uses amd64
# TARGETARCH is automatically set by Docker when building the image with the --platform flag
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ] ; then export ARCH="x64" ; else export ARCH=$TARGETARCH ; fi; \
    dotnet publish "PKHaX.csproj" -c Release -o /app/publish -r "linux-$ARCH"

FROM debian:12
WORKDIR /app

ENV PKHAX_PORT=9000
ENV PKHAX_PRIVATE_KEY_PATH=/app/private.key
EXPOSE 9000

RUN apt-get -y update && apt-get install -y libicu-dev libssl-dev

COPY --from=build /app/publish .

ENTRYPOINT ["./PKHaX"]
