## GraphQL exploitation

https://blog.doyensec.com/2018/05/17/graphql-security-overview.html

More to come.

Test for introspection:
```
GET /graphql?query={__schema{types{name}}}
```
