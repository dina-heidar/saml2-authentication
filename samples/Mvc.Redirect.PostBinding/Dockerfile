#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["samples/Mvc.Redirect.PostBinding/Mvc.Redirect.PostBinding.csproj", "samples/Mvc.Redirect.PostBinding/"]
RUN dotnet restore "samples/Mvc.Redirect.PostBinding/Mvc.Redirect.PostBinding.csproj"
COPY . .
WORKDIR "/src/samples/Mvc.Redirect.PostBinding"
RUN dotnet build "Mvc.Redirect.PostBinding.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Mvc.Redirect.PostBinding.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Mvc.Redirect.PostBinding.dll"]