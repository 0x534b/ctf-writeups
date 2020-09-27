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
Leak

# Challenge Points
317 pts

# Challenge Description
Git history repeats itself! \
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
First things first, let's clone the repo. We can see it doesn't contain much other than `README.md`:
```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/24/2020   4:30 PM                .git
d-----         9/24/2020   4:10 PM                .github
-a----         9/24/2020   4:10 PM           8319 README.md
```

The first thing I'll usually do in a challenge involving `git` is checking the commit history, especially when the description references it so blatantly. `git log` gives us this:
```
commit ee9470e5ca7592a9b596a6e4b1e5a225c80f18d3 (HEAD -> master, origin/master, origin/HEAD)
Author: Mat<C3><AD>as A. R<C3><A9> Medina <aereal@gmail.com>
Date:   Thu Sep 24 13:27:34 2020 -0400

    remove label requirement for issue filing so non-staff can file issues

commit cf407639990f339ca7a60021d0d2ccf3edfdfa8f
Author: Mat<C3><AD>as A. R<C3><A9> Medina <aereal@gmail.com>
Date:   Thu Sep 24 13:10:46 2020 -0400

    update

commit c21dbf5185a4dbdb5b2bd2f3d1d3b266c3a2271e
Author: Mat<C3><AD>as A. R<C3><A9> Medina <aereal@gmail.com>
Date:   Fri Sep 11 13:03:19 2020 -0400

    oops

commit fd5c9927bb9f5ee3e4c521def43d3033ae83b825
Author: Mat<C3><AD>as A. R<C3><A9> Medina <aereal@gmail.com>
Date:   Fri Sep 11 13:02:59 2020 -0400

    update

commit 8410559b915a311e1a66b2ef77b8f913c1bf9f2b
Author: Mat<C3><AD>as A. R<C3><A9> Medina <aereal@gmail.com>
Date:   Fri Sep 11 13:02:08 2020 -0400

    ekolabs
```

Most of these look pretty inconspicuous, except of course the one labeled "oops." Let's see what it changed using `git show c21dbf5185a4dbdb5b2bd2f3d1d3b266c3a2271e`:
```
commit c21dbf5185a4dbdb5b2bd2f3d1d3b266c3a2271e
Author: Mat<C3><AD>as A. R<C3><A9> Medina <aereal@gmail.com>
Date:   Fri Sep 11 13:03:19 2020 -0400

    oops

diff --git a/.ssh/id_rsa b/.ssh/id_rsa
deleted file mode 100644
index e96835e..0000000
--- a/.ssh/id_rsa
+++ /dev/null
@@ -1,38 +0,0 @@
------BEGIN OPENSSH PRIVATE KEY-----
-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
------END OPENSSH PRIVATE KEY-----
diff --git a/.ssh/id_rsa.pub b/.ssh/id_rsa.pub
deleted file mode 100644
index 3cf8765..0000000
--- a/.ssh/id_rsa.pub
+++ /dev/null
@@ -1 +0,0 @@
-ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDRKS8bh5B2ctUxrS0JsrlYmw/pJPOr7N3BRtdrdswXu7AnoxohsNX7D6gPt5oHb3Map2XMSqj3ukDrBWgL/qfiCfU4g5Fc1J4QkedDTiDq2+YeanaLgKyPqrvrg+lZwOIhfNXSliaxKI+YqgEy+n8s4ZhPGQYbpPjxDW/2ubn7iz60G+Px7q6BVvmRZlHe2IWylmG1WagL3pHFsJ83UyfgyFdvPqYoDkjVK+/+E4IGXaKXwHst2sVC+6DEU1YF3jJXFqeunY+Q3/dgxWXIbF7qpYGGJusEziHzjPX7Kwk4t1aW+afbREt7aDchx7KM/hDP/CBOYntwVA5qOG9L2rr6hbTTVMIqQxn2WAXtcBgc4Od4kMNAQt/8cvFsciApJ6RS++FPIwx8gJJCe/OZYdRl19/Fv+j9xi7dIiET4SqCUPz3nionKvMjvPvrd/42P9xw+niY+3gJEtIZjMb66Let+GuUew68bjz2DRlJSOtSNzP/MspNtUa5bY/4bmUMAHc= ekoparty-deploy@RUtPezc0NGFkN2ZlOGU2Y2U1ZTg4NWFkMjRlZWYyNDNiMWZkMTFkMGZiN2V9
```

Interesting, an `ssh` keypair. So, I actually didn't catch this the first time around but there's something weird going on at the end of `id_rsa.pub`:
```
ekoparty-deploy@RUtPezc0NGFkN2ZlOGU2Y2U1ZTg4NWFkMjRlZWYyNDNiMWZkMTFkMGZiN2V9
```

That looks like base 64 encoding! Decode it and we get the flag:
```
EKO{744ad7fe8e6ce5e885ad24eef243b1fd11d0fb7e}
```