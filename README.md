# Panalyzer

Let's analyze some password dumps! This is a character frequency analyzer that outputs hashcat masks and intersting frequency statistics using a password list as input. I started this for kicks, and decided to share. It's not yet complete. Threading doesn't really work yet thanks to GIL, and the keyspace feature isn't functinal yet either. The keyspace will (eventually) be used to generate custom hashcat char sets (of which hashcat supports 4) based on frequency...but not quite there yet.   

## Usage:

```
usage: panalyzer [-h] [-c] [-m] [-k] [-r] [--min MIN] [--max MAX] [-l LIMIT]
                 [-v] [-t THREADS]
                 passfile

Panalyzer - Lets analyze some passwords!

positional arguments:
  passfile              Password file to be processed.

optional arguments:
  -h, --help            show this help message and exit
  -c, --csv             Output as CSV
  -m, --mask            Generate hashcat mask based on character frequency
  -k, --keyspace        Output the keyspace of the password file
  -r, --rank            Output character frequency data
  --min MIN             Minimum string length to process, default 6
  --max MAX             Maximum string length to process, default 20
  -l LIMIT, --limit LIMIT
                        Limit frequency summaries to the top N results
  -v, --verbose         Increase output verbosity, -vv (very verbose)
  -t THREADS, --threads THREADS
                        Number of threads to analyze theinput, default 1

Panalyzer v1- Shawn Evans - sevans@nopsec.com

```

## Output exmpale:
```
turdbug@wtf:~/stuffnjunk$ ./panalyzer.py ~/wordlists/Top95Thousand-probable.txt -m --min 6 --max 10 -l 6
?l?l?l?l?l?l
?l?l?l?l?l?d
?l?l?l?l?d?d
?l?l?l?l?d?d
?l?d?l?l?d?d
?l?d?l?d?l?l
?l?l?l?l?l?l?d
?l?l?l?l?l?d?l
?l?l?l?l?l?l?d
?l?l?l?l?l?d?l
?l?l?d?d?d?d?d
?u?d?u?u?u?u?u
?l?l?l?l?l?l?l?d
?l?l?l?l?l?d?d?d
?l?l?l?l?l?l?d?d
?l?l?l?l?d?d?d?d
?l?l?l?l?u?u?u?u
?u?s?u?s?u?u?u?u
?l?l?l?l?l?l?l?d?d
?l?l?l?l?l?l?l?d?d
?l?l?l?l?l?l?d?l?d
?l?l?l?d?d?d?l?d?l
?u?u?u?u?u?u?u?u?s
?u?s?u?u?s?u?u?s?u
?l?l?l?l?l?l?l?l?l?d
?l?l?l?l?l?l?l?l?d?d
?l?l?l?l?l?d?d?d?d?d
?l?l?l?l?d?d?u?s?u?u
?u?u?u?u?u?s?u?u?s?u
?u?s?s?u?s?u?s?s?u?s

```

## Use the mask file with Haschat!

1. lets generate a mask from your favorite password list.

```
$ ./panalyzer.py ~/wordlists/password.lst -m --min 6 --max 10 -l 6 > ~/mymask.hcmask

```

2. Fire up hashcat for a mask attack.
```
$ hashcat -m 1000 --potfile-path dang_b.pot -a 3 hashes.txt ~/mymask.hcmask
```

3. Enjoy passwords :) 
