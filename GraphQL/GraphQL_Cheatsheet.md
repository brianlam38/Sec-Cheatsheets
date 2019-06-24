## GraphQL exploitation

GraphQL guides
* https://blog.doyensec.com/2018/05/17/graphql-security-overview.html
* https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/

GraphQL security toolkit
* https://github.com/doyensec/graph-ql

Test for introspection:
```
GET /graphql?query={__schema{types{name}}}
```

Other GraphQL endpoints:
```
/graphql/
/graphql/console/
/graphql.php
/graphiql/
/graphiql.php
```
