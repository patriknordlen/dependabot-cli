#!/usr/bin/env python

import json
import os
import sys
from argparse import ArgumentParser
from base64 import b64decode
from datetime import datetime
from multiprocessing import Pool

import requests
from codeowners import CodeOwners
from progress.bar import ShadyBar
from tabulate import tabulate


class GithubClient:
    def __init__(self, gh_token, baseurl="https://api.github.com"):
        self.gh_token = gh_token
        self.baseurl = baseurl

    def __get(self, endpoint, *args, **kwargs):
        r = requests.get(
            url=f"{self.baseurl}{endpoint}", *args, **kwargs, headers={"Authorization": f"token {self.gh_token}"}
        )

        if r:
            results = r.json()
            while "next" in r.links:
                r = requests.get(
                    r.links["next"]["url"],
                    headers={"Authorization": f"token {self.gh_token}"},
                )
                results.extend(r.json())

            return results
        else:
            return None

    def get_org_repos(self, org):
        repos = self.__get(
            f"/orgs/{org}/repos?per_page=100&type=all"
        )

        if repos:
            return [repo["full_name"] for repo in repos if not repo["archived"]]
        else:
            return None

    def get_owners(self, repo):
        codeowners_response = self.__get(
            f"/repos/{repo}/contents/.github/CODEOWNERS"
        )

        if codeowners_response:
            codeowners = CodeOwners(b64decode(codeowners_response["content"]).decode())
            return [owner[1] for owner in codeowners.of("/")]
        else:
            return []

    def get_dependabot_alerts(self, repo):
        alerts = self.__get(
            f"/repos/{repo}/dependabot/alerts?state=open&first=100"
        )

        if alerts:
            owners = self.get_owners(repo)
            reduced_alerts = [
                {
                    "repo": repo,
                    "owners": owners,
                    "severity": alert["security_vulnerability"]["severity"],
                    "summary": alert["security_advisory"]["summary"],
                    "created_at": alert["created_at"],
                    "age_in_days": (
                        datetime.now()
                        - datetime.strptime(alert["created_at"], "%Y-%m-%dT%H:%M:%SZ")
                    ).days,
                }
                for alert in alerts
                if "security_advisory" in alert
            ]

            return reduced_alerts
        else:
            return []

    def check_vuln_alert_status(self, repo):
        r = requests.get(
            f"/repos/{repo}/vulnerability-alerts",
            headers={"Authorization": f"token {self.gh_token}"},
        )

        return r.status_code == 204


def main():
    alerts = []
    parser = ArgumentParser()
    parser.add_argument(
        "-s", "--severities", help="Comma-separated list of severities to include"
    )
    parser.add_argument(
        "-f",
        "--format",
        help="Output format. Any format supported by tabulate works.",
        default="psql",
    )
    parser.add_argument("--min-age", type=int)
    parser.add_argument("--max-age", type=int)
    parser.add_argument("-t", "--team")
    parser.add_argument("--threads", default=5, type=int)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-r", "--repos", help="Comma-separated list of repositories to check"
    )
    group.add_argument(
        "-o", "--org", help="Organization to search for repos in", default="einride"
    )

    args = parser.parse_args()

    if os.environ.get("GH_TOKEN") is None:
        print(
            "You need to set the environment variable GH_TOKEN to a valid GitHub personal access token."
        )
        sys.exit(1)

    gh = GithubClient(gh_token=os.environ.get("GH_TOKEN"))

    if args.repos:
        repos = args.repos.split(",")
    else:
        repos = gh.get_org_repos(args.org)
        if not repos:
            print(
                "Couldn't get repository list. Check that the provided Github access token is valid and has access to Dependabot alerts."
            )
            sys.exit(1)

    with ShadyBar("Getting repo alerts", max=len(repos)) as bar:
        pool = Pool(processes=args.threads)
        for result in pool.imap_unordered(gh.get_dependabot_alerts, repos):
            alerts.extend(result)
            bar.next()

    if args.min_age:
        alerts = list(
            filter(lambda alert: alert["age_in_days"] >= args.min_age, alerts)
        )

    if args.max_age:
        alerts = list(
            filter(lambda alert: alert["age_in_days"] <= args.max_age, alerts)
        )

    if args.severities:
        alerts = list(
            filter(lambda alert: alert["severity"] in args.severities, alerts)
        )

    if args.team:
        alerts = list(
            filter(lambda alert: args.team in alert["owners"], alerts)
        )

    alerts.sort(key=lambda x: x.get("repo"))

    if args.format == "json":
        print(json.dumps(alerts))
    else:
        print(tabulate(alerts, headers="keys", tablefmt=args.format))


if __name__ == "__main__":
    main()
