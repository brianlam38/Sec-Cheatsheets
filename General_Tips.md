# General Tips

Modify your payloads slightly to bypass parsers / filters.
* Example: A filter that will reject `file:///` or `<script>` but accept `FilE:///` or `<ScRipT>`

Encode your payload: i.e. base64 or URL-encode

Test for common URL paths.
```
/admin
```

Look in source code:
* i.e. `Inspect -> View Source` to find flags. They might be hiding there as a comment etc.
