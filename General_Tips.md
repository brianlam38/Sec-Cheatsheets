# General Tips

* Modify your payloads slightly to bypass parsers etc.
  * Example: A filter that will reject `file:///` or `<script>` but accept `FilE:///` or `<ScRipT>`
  * Encode your payload: i.e. base64 or URL-encode
