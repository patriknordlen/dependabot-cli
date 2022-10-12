#!/usr/bin/env python

import requests
from collections import Counter
import os

gh_token = os.environ.get("GH_TOKEN")


def get_org_repos(org):
    r = requests.get(
        f"https://api.github.com/orgs/{org}/repos?per_page=100&type=all",
        headers={"Authorization": f"token {gh_token}"},
    )
    results = r.json()
    while "next" in r.links:
        r = requests.get(
            r.links["next"]["url"], headers={"Authorization": f"token {gh_token}"}
        )
        results.extend(r.json())

    return results


def get_dependabot_alerts(repo):
    r = requests.get(
        f"https://api.github.com/repos/{repo}/dependabot/alerts?state=open&first=100",
        headers={"Authorization": f"token {gh_token}"},
    )
    alerts = r.json()
    while "next" in r.links:
        r = requests.get(
            r.links["next"]["url"], headers={"Authorization": f"token {gh_token}"}
        )
        alerts.extend(r.json())

    severities = [
        f"{sev}: {count}"
        for sev, count in Counter(
            [
                alert["security_vulnerability"]["severity"]
                for alert in alerts
                if "security_vulnerability" in alert
            ]
        ).items()
    ]
    if severities:
        print(f"{repo}: {' '.join(severities)}")


def main():
    org = "einride"

    for repo in get_org_repos(org):
        get_dependabot_alerts(repo["full_name"])


if __name__ == "__main__":
    main()