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
Docs

# Challenge Points
420 pts

# Challenge Description
Always check the docs! \
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
This challenge is actually a continuation of the previous one, `Leak`. You could check out my writeup for `Leak`, but basically so far we have cloned a `GitHub` repository and found an `ssh` keypair in a previous commit. After looking through the `GitHub` documentation as the challenge name and description suggests, I found that an `ssh` key can be used to allow limited access to repositories without using a password.

Let's `git checkout` the commit right before the files were removed then see what we can do with them.

First, we need to set the private key's permissions correctly, otherwise we can't use it. We can do that like this:
```
chmod 600 <path to repo>/ekolabs/.ssh/id_rsa
```

Next, we need to tell `ssh` to use this key when we want it to. One way to do this is to add a host to our `~/.ssh/config` file with the following lines:
```
host gh-as-ekoparty
    HostName github.com
    IdentityFile <path to repo>/ekolabs/.ssh/id_rsa
    User git
```

With this, `ssh` will expand `gh-as-ekoparty` to `git@github.com` and use our provided keys. Now lets test our connection with `ssh -T gh-as-ekoparty`:
```
Hi ekoparty2020/ekoparty-internal! You've successfully authenticated, but GitHub does not provide shell access.
```

Awesome! It looks like we now can access a private repository at `ekoparty2020/ekoparty-internal`. Let's try and clone it with `git clone gh-as-ekoparty:ekoparty2020/ekoparty-internal.git`:
```
Cloning into 'ekoparty-internal'...
Warning: Permanently added the RSA host key for IP address '140.82.114.3' to the list of known hosts.
remote: Enumerating objects: 7, done.
remote: Counting objects: 100% (7/7), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 7 (delta 0), reused 7 (delta 0), pack-reused 0
Receiving objects: 100% (7/7), done.
```

Nice! We can take a look at `README.md`:
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