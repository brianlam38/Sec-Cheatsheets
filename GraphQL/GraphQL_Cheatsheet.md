## GraphQL exploitation

GraphQL guides
* https://blog.doyensec.com/2018/05/17/graphql-security-overview.html
* https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/

GraphQL security toolkit
* https://github.com/doyensec/graph-ql


More to come.

Test for introspection:
```
GET /graphql?query={__schema{types{name}}}
```
