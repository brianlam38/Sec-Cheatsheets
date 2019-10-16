## GraphQL exploitation

GraphQL guides
* https://blog.doyensec.com/2018/05/17/graphql-security-overview.html
* https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/
* https://medium.com/@localh0t/discovering-graphql-endpoints-and-sqli-vulnerabilities-5d39f26cea2e

GraphQL security toolkit
* https://github.com/doyensec/graph-ql

Test for introspection:
```
GET /graphql?query={__schema{types{name}}}
```

/graphql not working? Try the following:
```
/graphql/
/graphql/console/
/graphql.php
/graphiql/
/graphiql.php
```

GraphQL SQLi writeups
* https://hackerone.com/reports/435066

GraphQL API hacking
* http://ghostlulz.com/api-hacking-graphql/
