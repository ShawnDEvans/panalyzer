#! /usr/bin/env python3
import concurrent.futures
import threading
import logging
import sys
import time
import operator
import os
import re
from functools import reduce

class CharClass(dict):
    def __init__(self, pass_length, password=None):
        '''
        Generates a character class dictionary to keep track of character frequency.
        '''
        if password:
            ascii_set = [ ord(item) for item in list(password.strip()) ]
        else:
            ascii_set = range(32, 127)
        chars = [ chr(x) for x in ascii_set ] 
        char_class = { c: [0] * pass_length for c in chars }
        self.update(char_class)

class Matrix(dict):
     
    def __init__(self, min_len=5, max_len=20, infile=None, verbose=False, threads=1):
        logFormat = '[*] %(message)s' 
        if verbose == 1:
            logging.basicConfig(format=logFormat, level=logging.INFO)
        elif verbose == 2:
            logging.basicConfig(format=logFormat+' - %(asctime)s', level=logging.DEBUG)
        else:
            logging.basicConfig()
    
        self.result = {}
        pass_matrix = {}
        self.stats = {}
        self.mymask = [] 
 
        for val in range(min_len, max_len+1):
            pass_matrix[val] = CharClass(val)
        self.update(pass_matrix)
        
        if infile:
            passwords = infile.readlines()
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=int(threads)) as executor:
                    start = time.time()
                    processed_raw = executor.map(self.process, passwords)
                infile.close()
                 
            except IOError as e:
                logging.error('[!] Invalid or missing input file...')
                sys.exit()
            except Exception as e:
                logging.error('[!] Something went wrong with the threads...{}'.format(e) )
                pass
            logging.info('Processed passwords from {} in: {}'.format(os.path.basename(infile.name), time.time() - start))

    def process(self, password):
        password = password.strip()
        pass_len = len(password)
        entry = {}
        entry[pass_len] = CharClass(pass_len, password) 
        try:
            for position, char in enumerate(password):
                self[pass_len][char][position] += 1
            self.stats[pass_len] = self.stats[pass_len]+1 if pass_len in list(self.stats.keys()) else 0
        except KeyError:
            logging.debug('[!] Password exceeded length boundaries: {}'.format(password))
            pass

    def summary(self, slots):
        row = {}
        processed_values = {}
        top_freq = 0
        freq = 0
        total = sum( [ self.stats[item] for item in list(self.stats.keys()) ] )
     
        for pwlength in self.keys():
            processed_values[pwlength] = [] 
            for position in range(pwlength):
                row = [ (freq, char, round(freq/total, 4) ) for freq, char in zip( [ self[pwlength][key][position] for key in self[pwlength].keys() ], self[pwlength].keys() ) ]
                processed_values[pwlength].append(sorted(row)[::-1])
        
        for pwlength in processed_values.keys():
            self.result[pwlength] = []
            try: 
                logging.info('Summary for length: {} ({}%)'.format(pwlength, round((self.stats[pwlength]/total)*100,2) ) )
                for rank in range(slots):
                    row = [ processed_values[pwlength][position][rank] for position in range(pwlength) ]
                    logging.info('{}. {}'.format(rank+1, row)) 
                    self.result[pwlength].append(row)
            except Exception as e:
                continue
 
        return True 
     
    def mask(self, cust=False):
        final = [] 
        mymask = ''
        for length in list(self.result.keys()):
            mask = {}
            for rank, row in enumerate(self.result[length]):
                #print('[*] Rank {}: {}'.format(rank+1, row))
                mask[rank] = [ self.char_to_mask(char) for freq, char, prob in row ]
                mymask = ''.join(mask[rank])
                final.append(mymask)
        uniq_mask = sorted(set(final), key=len)

        if not cust:
            for bam in sorted(set(final), key=len):
                print(bam)

        self.mymask = uniq_mask 

    def keyspace(self):
        ''' 
        This doesn't work atm...
        '''
        output = {}
        if len(self.result.keys()) > 0:
            for length in self.result.keys():
                keyspace = []
                for rank, row in enumerate(self.result[length]):
                    keyspace.append( [ char for freq, char, prob in row ] )
                output[length] = sorted(set(reduce(operator.concat, keyspace)))
        
        self.mask(True)
        cust_def = {} 
        for length in output.keys():
            cust_lower = []
            cust_upper = []
            cust_digit = []
            cust_spec = []
            for item in output[length]:
                val_type = self.char_to_mask(item)
                if val_type == '?l':
                    cust_lower.append(item)
                elif val_type == '?u':
                    cust_upper.append(item)
                elif val_type == '?d':
                    cust_digit.append(item)
                else:
                    cust_spec.append(item)
            cust_def[length] = '{},{},{},{}'.format(''.join(cust_lower), ''.join(cust_upper), ''.join(cust_digit), ''.join(cust_spec)) 

        for mask in self.mymask:
            cust_mask = mask.replace('l','1').replace('u','2').replace('d','3').replace('s','4')
            print('{},{}'.format( cust_def[len(mask)/2], cust_mask)) 

    def csv(self):
        import csv
        import io
        if len(list(self.result.keys())) > 0:
            header = [ 'Length', 'Rank', 'Position', 'Char', 'Freq' ]
            output= io.StringIO()
            wr = csv.writer(output, delimiter=',', quoting=csv.QUOTE_ALL)
            wr.writerow( header )
            for length in list(self.result.keys()):
                for rank, row in enumerate(self.result[length]):
                    for pos, values in enumerate(row):
                        wr.writerow( [ length, rank+1, pos+1, values[1], values[0] ] )
            contents = output.getvalue()
            print(contents)

    def to_string(self):
        rank = 1
        total = sum( [ self.stats[item] for item in list(self.stats.keys()) ] )
        most_common = max([ (item, self.stats[item]) for item in list(self.stats.keys()) ] , key=operator.itemgetter(1) )
        print('[*] Total passwords analyzed: {}'.format( total ))
        print('[*] Average password length: {}'.format( sum( [ item*self.stats[item] for item in list(self.stats.keys()) ] ) / total ))
        print('[*] Most common password length: {} ({} or {}%)'.format( *most_common+( round((most_common[1] / float(total))*100, 2), ) ))

    def show_rank(self):
        rank = 1
        total = sum( [ self.stats[item] for item in list(self.stats.keys()) ] )
        
        for length in self.result.keys():
            try:
                print('[*] Character frequency analysis completed for length: {}, Passwords: {} ({}%)'.format(length, self.stats[length], round((self.stats[length]/total)*100, 2))) 
                for row in self.result[length]:
                    print('[*] {}. {}'.format(rank, [ (freq, char) for freq,char,prob in row]))
                    rank += 1
                rank = 1
            except:
                continue

    def char_to_mask(self, char):
        upper = '[A-Z]'
        lower = '[a-z]'
        digit = '[0-9]'
        special = '[\  \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\]\^_\`\{\|\}\~]'
        if re.search(upper, char):
            return '?u'
        elif re.search(lower, char):
            return '?l'
        elif re.search(digit, char): 
            return '?d'
        elif re.search(special, char): 
            return '?s'
        else:
            return '?a'

