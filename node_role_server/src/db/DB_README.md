## Calculate flags:

```
ioc  yara  sigma    flags
-------------------------
false false false     0
true  false false     1
false true  false     2
true  true  false     3
false false true      4
true  false true      5
false true  true       6
true  true  true       7
```
## What we need to do
- Find events who have got all 2 checks then run a consensus check

Long term goal would be to integrate this with some better telemetry handling microservices like elastic, maybe, idk.