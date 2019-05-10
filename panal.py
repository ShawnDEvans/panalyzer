#! /usr/bin/env python

import argparse
import password
import sys
import pprint
import logging

def analyze(passlist):
    pass

def main():
    parser = argparse.ArgumentParser(description='Analyze some passwords.')
    parser.add_argument('passfile', help='Password file to be processed.')
    parser.add_argument('-c', '--csv', help='Output as CSV', action='store_true')
    parser.add_argument('-m', '--mask', help='Generate hashcat mask based on character frequency', action='store_true')
    parser.add_argument('-k', '--keyspace', help='Output the keyspace of the password file',action='store_true')
    parser.add_argument('--min', type=int, help='Minimum string length to process, default  %(default)s', default=6)
    parser.add_argument('--max', type=int, help='Maximum string length to process, default  %(default)s', default=20)
    parser.add_argument('-l', '--limit', type=int, help='Limit frequency summaries to the top N results', default=15)
    parser.add_argument('-v', '--verbose', help='Increase output verbosity', action='store_true')
    args = parser.parse_args()
    
    with open(args.passfile) as infile:
        analyzer = password.Matrix(args.min, args.max, infile, args.verbose)
        analyzer.summary(args.limit)
        try:
            if args.csv:
                analyzer.csv()
            elif args.mask:
                analyzer.mask()
            elif args.keyspace:
                #currently broken feature
                #analyzer.keyspace()
            else:
                analyzer.to_string()
        except Exception as e:
            logging.exception('[!] General analyzer failure')

        
if __name__ == "__main__":
    main() 
