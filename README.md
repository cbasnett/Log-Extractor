# Tools

## Log Extractor

A tool to extract Windows Event Logs into a reasonably usable json format for use with Elasticsearch, JQ, Grep, whatever..

Tested on Windows 10 and Windows 7. Code functional rather than pretty.

```
usage: log_extract.exe [-h] [-g] -o OUTPUT [-v]

Log Collector

optional arguments:
  -h, --help            show this help message and exit
  -g, --gzip            Compress with GZIP
  -o OUTPUT, --output OUTPUT
                        Output Directory
  -v, --version         show program's version number and exit
  ```
  
