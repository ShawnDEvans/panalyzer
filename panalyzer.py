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
    start_time = time.time()
    overall_start = time.time()

    parser = argparse.ArgumentParser(prog='panalyzer', description='Panalyzer - Lets analyze some passwords!', epilog='Panalyzer v1- Shawn Evans - sevans@nopsec.com')
    parser.add_argument('passfile', help='Password file to be processed.')
    parser.add_argument('-c', '--csv', help='Output as CSV', action='store_true')
    parser.add_argument('-m', '--mask', nargs='?', const='stdout', default=None, help='Generate hashcat mask based on character frequency and write to a specified file, or stdout if no file is specified.')
    parser.add_argument('-k', '--keyspace', nargs='?', const='stdout', default=None, help='Output the keyspace of the password file to a specified file, or stdout if no file is specified.')
    parser.add_argument('-r', '--rank', help='Output character frequency data', action='store_true')
    parser.add_argument('--min', type=int, help='Minimum string length to process, default  %(default)s', default=6)
    parser.add_argument('--max', type=int, help='Maximum string length to process, default  %(default)s', default=12)
    parser.add_argument('-l', '--limit', type=int, help='Limit frequency summaries to the top N results', default=15)
    parser.add_argument('-v', '--verbose', help='Increase output verbosity, -vv (very verbose)', action='count', default=0)
    args = parser.parse_args()

    # Default to ERROR logging unless explicit verbosity flags are supplied
    logging.basicConfig(
        format='[%(levelname)s] %(message)s',
        level=logging.ERROR if not args.verbose else (logging.DEBUG if args.verbose > 1 else logging.INFO)
    )

    try:
        with open(args.passfile, encoding='utf-8', errors='ignore') as infile:
            analyzer = password.Matrix(args.min, args.max, infile, args.verbose)

            data_collection_time = time.time() - overall_start
            logging.info(f"Data collection took: {data_collection_time:.2f} seconds")

            analyzer.summary(args.limit)

            if args.csv:
                analyzer.csv()
            elif args.mask:
                analyzer.mask(out_file=args.mask)
            elif args.keyspace:
                analyzer.keyspace(out_file=args.keyspace)
            elif args.rank:
                analyzer.show_rank()
            else:
                analyzer.to_string()

    except Exception as e:
        logging.exception('[!] General analyzer failure...{}'.format(e))

    total_time = time.time() - start_time
    logging.info(f"Total execution time: {total_time:.2f} seconds")

if __name__ == "__main__":
    main()
