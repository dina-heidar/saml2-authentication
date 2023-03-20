#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["samples/Blazor.Artifact.PostBinding/Blazor.Artifact.PostBinding.csproj", "samples/Blazor.Artifact.PostBinding/"]
RUN dotnet restore "samples/Blazor.Artifact.PostBinding/Blazor.Artifact.PostBinding.csproj"
COPY . .
WORKDIR "/src/samples/Blazor.Artifact.PostBinding"
RUN dotnet build "Blazor.Artifact.PostBinding.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Blazor.Artifact.PostBinding.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Blazor.Artifact.PostBinding.dll"]