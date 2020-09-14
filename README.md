# Firewall Syslog

A quick and dirty program to receive syslog from my firewall and push into a SQL Server database.

## How to run

```cmd
C:\> go run .\main.go --help
Usage of ...\main.exe:
  -Database string
        Database where logs are written to.
  -Password string
        Password to connect to Sql Server Database.
  -Port int
        Port of the Sql Server. (default 1433)
  -SqlServer string
        Address of the Sql Server.
  -Username string
        Username to connect to Sql Server Database.
```

## Disclaimer

Don't use this in production!!!

## Todo

- [ ] Add dockerfile
- [ ] Refactor
- [ ] Fix crash upon failed regex match
