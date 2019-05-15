# Panalyzer

Let's analyze some password dumps! This is a character frequency analyzer that outputs hashcat masks and intersting frequency statistics using a password list as input. I started this for kicks, and decided to share. It's not yet complete and performance could be a bit better, but the output appears accurate - so I've got that going for me. 

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

## Generate a mask with custom charset:
Keyspace is king in the world of brute force, and any reduction of the keyspace results in cracking efficiency gains. With this in mind, the keyspace feature analyzses postional frequency trends and retunrs only those characters found in the top 'N' results, just like below. (btw - don't worry if there isn't a 1:1 between ranked results and masks, duplicate masks are removed)  
```
$ ./panalyzer.py --min 7 --max 10 -l 15 cracked_pws.txt -k
abcdefghijklmnoprstuy,,0123456789,!,?1?1?1?1?1?1?1
abcdefghijklmnoprstuy,,0123456789,!,?1?1?1?1?1?3?1
abcdefghijklmnoprstuy,,0123456789,!,?1?1?1?1?1?1?3
abcdefghijklmnoprstuy,,0123456789,!,?1?1?1?3?3?1?3
abcdefghijklmnoprstuy,,0123456789,!,?1?1?1?1?1?3?3
abcdefghijklmnoprstuy,,0123456789,!,?1?3?1?1?1?1?4
abcdefghijklmnoprstuy,,0123456789,!,?1?1?1?1?3?3?3
abcdeghiklmnoprstuy,ABCDFJKLMNPRST,0123456789,!$*@,?2?1?1?1?1?3?3?4
abcdeghiklmnoprstuy,ABCDFJKLMNPRST,0123456789,!$*@,?2?1?1?1?1?1?3?3
abcdeghiklmnoprstuy,ABCDFJKLMNPRST,0123456789,!$*@,?2?1?1?1?3?3?3?3
abcdeghiklmnoprstuy,ABCDFJKLMNPRST,0123456789,!$*@,?2?1?1?1?1?3?1?4
abcdeghiklmnoprstuy,ABCDFJKLMNPRST,0123456789,!$*@,?1?1?1?1?1?3?1?1
abcdeghiklmnoprstuy,ABCDFJKLMNPRST,0123456789,!$*@,?2?1?1?1?1?3?3?3
abcdeghiklmnoprstuy,ABCDFJKLMNPRST,0123456789,!$*@,?2?1?1?1?1?3?1?3
abcdeghiklmnoprstuy,ABCDFJKLMNPRST,0123456789,!$*@,?2?1?1?1?1?1?1?4
abcdeghiklmnoprstuy,ABCDFJKLMNPRST,0123456789,!$*@,?2?1?1?1?3?1?3?3
abcdehiklmnoprstuy,ABCDFHJLMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?3?3?3?4
abcdehiklmnoprstuy,ABCDFHJLMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?3?1?3
abcdehiklmnoprstuy,ABCDFHJLMNPRSTW,0123456789,!#$*@,?2?1?1?1?3?1?1?3?3
abcdehiklmnoprstuy,ABCDFHJLMNPRSTW,0123456789,!#$*@,?2?1?1?1?4?1?3?1?4
abcdehiklmnoprstuy,ABCDFHJLMNPRSTW,0123456789,!#$*@,?2?1?1?1?3?1?1?1?4
abcdehiklmnoprstuy,ABCDFHJLMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?3?3?3?3
abcdehiklmnoprstuy,ABCDFHJLMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?3?1?4
abcdehiklmnoprstuy,ABCDFHJLMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?3?3?3
abcdehiklmnoprstuy,ABCDFHJLMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?1?3?3
abcdehiklmnoprstuy,ABCDFHJLMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?4?1?4
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?4?1?1?3?1?1?3?1?4
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?3?1?3?3
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?1?1?1?1?1?3?1?1?3?3
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?1?3?3?3
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?3?1?3?4?4
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?3?1?1?3?3
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?1?3?1?4
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?3?3?3?3
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?1?1?1?3
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?3?3?3?4
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?1?1?3?3
abcdehiklmnoprstuwy,ABCDFJKMNPRSTW,0123456789,!#$*@,?2?1?1?1?1?1?3?1?1?4

```

## Password frequency stats:
'''
$ ./panalyzer.py --min 7 --max 10 -l 5 ~/wordlists/password.lst -r
[*] Character frequency analysis completed for length: 7, Passwords: 606 (43.22%)
[*] 1. [(65, 's'), (110, 'a'), (64, 'n'), (60, 't'), (81, 'i'), (106, 'e'), (74, 'e')]
[*] 2. [(56, 'c'), (96, 'e'), (57, 'a'), (45, 'r'), (81, 'e'), (70, 'r'), (63, 's')]
[*] 3. [(39, 'b'), (79, 'o'), (56, 'r'), (44, 'e'), (61, 'a'), (61, 'n'), (60, 'n')]
[*] 4. [(38, 'p'), (66, 'i'), (54, 'c'), (42, 'n'), (49, 'o'), (52, 'i'), (55, 'r')]
[*] 5. [(38, 'm'), (48, 'u'), (43, 'l'), (35, 'i'), (40, 't'), (47, 'o'), (49, 'y')]
[*] Character frequency analysis completed for length: 8, Passwords: 561 (40.01%)
[*] 1. [(41, 'c'), (99, 'a'), (61, 'r'), (63, 'e'), (45, 'e'), (62, 'e'), (59, 'a'), (52, 'e')]
[*] 2. [(37, 's'), (79, 'o'), (48, 'n'), (47, 'n'), (38, '2'), (57, 'i'), (54, 'e'), (39, 's')]
[*] 3. [(32, 'm'), (61, 'e'), (48, 'c'), (43, 't'), (36, 'a'), (43, 'a'), (38, 'n'), (38, 'n')]
[*] 4. [(25, 'a'), (59, 'i'), (46, 'a'), (33, 'r'), (35, 'i'), (33, 'r'), (35, 'r'), (35, 'r')]
[*] 5. [(22, 'p'), (39, 'r'), (40, 'o'), (28, 'a'), (34, 'l'), (33, 'n'), (34, 'i'), (35, '1')]
[*] Character frequency analysis completed for length: 9, Passwords: 166 (11.84%)
[*] 1. [(12, 'P'), (32, 'a'), (18, 'a'), (13, 'e'), (24, 'e'), (17, '2'), (14, 'o'), (22, '1'), (22, '1')]
[*] 2. [(12, 'B'), (20, 'o'), (15, 'c'), (11, 'n'), (16, 'a'), (15, 'r'), (14, '3'), (21, '2'), (16, '5')]
[*] 3. [(11, 's'), (20, 'e'), (14, 'n'), (10, 'o'), (14, 's'), (15, '1'), (12, 'e'), (11, 'e'), (14, 'e')]
[*] 4. [(11, 'c'), (17, 'i'), (14, 'l'), (9, 'l'), (10, 'o'), (11, 'l'), (11, '1'), (9, 'o'), (14, '3')]
[*] 5. [(11, 'A'), (15, 'h'), (12, 'o'), (9, 'c'), (9, 'n'), (10, 'n'), (11, '0'), (9, 'n'), (12, '9')]
[*] Character frequency analysis completed for length: 10, Passwords: 69 (4.92%)
[*] 1. [(10, 'B'), (15, 'o'), (8, 'n'), (9, 'e'), (8, 'e'), (6, 'o'), (12, '1'), (9, '0'), (16, '1'), (10, '5')]
[*] 2. [(7, 'M'), (15, 'a'), (8, 'c'), (7, 'n'), (7, '1'), (6, 'n'), (8, '2'), (5, '5'), (8, '6'), (9, '1')]
[*] 3. [(4, 'S'), (8, 'i'), (7, 's'), (5, 't'), (6, 'i'), (6, 'e'), (7, 'r'), (5, '4'), (6, 'l'), (7, '6')]
[*] 4. [(4, 'A'), (8, 'e'), (7, 'i'), (5, 's'), (5, 'a'), (5, 'a'), (6, 'e'), (5, '2'), (5, '5'), (4, '8')]
[*] 5. [(3, 'p'), (5, 'h'), (6, 'v'), (4, 'r'), (5, '2'), (5, '2'), (4, 'n'), (4, 'r'), (5, '4'), (4, '7')]

'''

## Use a mask file or custom charset with Haschat

1. lets generate a mask from your favorite password list.

```
$ ./panalyzer.py ~/wordlists/password.lst -m --min 6 --max 10 -l 6 > ~/mymask.hcmask

```

2. Fire up hashcat for a mask attack.
```
$ hashcat -m 1000 -O -w 3 -a 3 hashes.txt ~/mymask.hcmask
```

3. Enjoy passwords :) 
