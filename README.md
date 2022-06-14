# MS Exchange CVS-Scanner

An automated nmap Scanner for MS Exchange installations to check for the latest CU and SU updates and linked CVSs.
The scanning results are prepared as Markdown files and serverd with a simple webserver as HTML and downloadable as markdown.

The nmap script is from [righel/ms-exchange-version-nse](https://github.com/righel/ms-exchange-version-nse)

To scan, just run the script with different networks/hosts like this daily as a cronjob:

```bash
$ python exchange_scan.py HOST [HOST, ...]
```

To check the reports, run the simple http server:

```bash
$ python server.py
```
