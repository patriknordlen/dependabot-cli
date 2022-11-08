#!/usr/bin/env python

import os
from argparse import ArgumentParser
from datetime import datetime
import requests
import sys
from tabulate import tabulate
from progress.bar import ShadyBar


class GithubClient:
    def __init__(self, gh_token):
        self.gh_token = gh_token

    def __get(self, *args, **kwargs):
        r = requests.get(
            *args, **kwargs, headers={"Authorization": f"token {self.gh_token}"}
        )
        results = r.json()
        while "next" in r.links:
            r = requests.get(
                r.links["next"]["url"],
                headers={"Authorization": f"token {self.gh_token}"},
            )
            results.extend(r.json())

        return results

    def get_org_repos(self, org):
        repos = self.__get(
            f"https://api.github.com/orgs/{org}/repos?per_page=100&type=all"
        )

        return [repo["full_name"] for repo in repos if not repo["archived"]]

    def get_dependabot_alerts(self, repo):
        alerts = self.__get(
            f"https://api.github.com/repos/{repo}/dependabot/alerts?state=open&first=100"
        )

        reduced_alerts = [
            {
                "repo": repo,
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

    def check_vuln_alert_status(self, repo):
        r = requests.get(
            f"https://api.github.com/repos/{repo}/vulnerability-alerts",
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

    with ShadyBar("Getting repo alerts", max=len(repos)) as bar:
        for repo in repos:
            alerts.extend(gh.get_dependabot_alerts(repo))
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

    alerts.sort(key=lambda x: x.get("repo"))

    print(tabulate(alerts, headers="keys", tablefmt=args.format))


if __name__ == "__main__":
    main()
