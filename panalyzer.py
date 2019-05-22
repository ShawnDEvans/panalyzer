#! /usr/bin/env python3

import argparse
import password
import sys
import pprint
import logging
import time

def analyze(passlist):
    pass

def main():
    start = time.time()
    
    parser = argparse.ArgumentParser(prog='panalyzer', description='Panalyzer - Lets analyze some passwords!', epilog='Panalyzer v1- Shawn Evans - sevans@nopsec.com')
    parser.add_argument('passfile', help='Password file to be processed.')
    parser.add_argument('-c', '--csv', help='Output as CSV', action='store_true')
    parser.add_argument('-m', '--mask', help='Generate hashcat mask based on character frequency', action='store_true')
    parser.add_argument('-k', '--keyspace', help='Output the keyspace of the password file',action='store_true')
    parser.add_argument('-r', '--rank', help='Output character frequency data', action='store_true')
    parser.add_argument('--min', type=int, help='Minimum string length to process, default  %(default)s', default=6)
    parser.add_argument('--max', type=int, help='Maximum string length to process, default  %(default)s', default=12)
    parser.add_argument('-l', '--limit', type=int, help='Limit frequency summaries to the top N results', default=15)
    parser.add_argument('-v', '--verbose', help='Increase output verbosity, -vv (very verbose)', action='count', default=0)
    parser.add_argument('-t', '--threads', help='Number of threads to analyze theinput, default %(default)s', default=1)
    args = parser.parse_args()
    
    with open(args.passfile, encoding='utf-8', errors='ignore') as infile:
        analyzer = password.Matrix(args.min, args.max, infile, args.verbose, args.threads)
        analyzer.summary(args.limit)
        try:
            if args.csv:
                analyzer.csv()
            elif args.mask:
                analyzer.mask()
            elif args.keyspace:
                analyzer.keyspace()
                pass
            elif args.rank:
                analyzer.show_rank()
            else:
                analyzer.to_string()
            end = time.time()
        except Exception as e:
            logging.exception('[!] General analyzer failure...{}'.format(e))

        
if __name__ == "__main__":
    main() 
