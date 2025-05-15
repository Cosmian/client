## MacOS

```zsh
docker pull mcr.microsoft.com/mssql/server:2022-latest
docker run -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=Password@92" \
   -p 1433:1433 --name sql2022 --hostname sql2022 \
   -d \
   mcr.microsoft.com/mssql/server:2022-latest
```

