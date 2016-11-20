# mysqlproxy
The simple mysql proxy allows to log every query and replace credentials for server on flight.

buid
====

go build .

usage
=====
```
mysqlproxy -l "listen address" -s "server address" [-u "server username" -p "server password"]
```
