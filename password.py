#! /usr/bin/env
import concurrent.futures
import threading
import logging
import sys
import time
import operator
import os
import re

class CharClass(dict):
    def __init__(self, pass_length, password=None):
        if password:
            ascii_set = [ ord(item) for item in list(set(password)) ]
        else:
            ascii_set = list(range(32, 127))
        chars = [ chr(x) for x in ascii_set ] 
        char_class = { c: [0] * pass_length for c in chars }
        self.update(char_class)

class Matrix(dict):
     
    def __init__(self, min_len=5, max_len=20, infile=None, verbose=False, threads=1):
        logFormat = '%(message)s - %(asctime)s - %(levelname)s'
        if verbose == 1:
            logging.basicConfig(format=logFormat, level=logging.INFO)
        elif verbose == 2:
            logging.basicConfig(format=logFormat, level=logging.DEBUG)
        else:
            logging.basicConfig()
    
        self.result = {}
        pass_matrix = {}
        self.stats = {}
 
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
            logging.info('[+] Processed passwords from {} in: {}'.format(os.path.basename(infile.name), time.time() - start))

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
        
        for pwlength in list(self.keys()):
            ranked_values = [] 
            row[pwlength] = [ [('',0)] * pwlength for x in range(slots) ] 
            processed_values[pwlength] = [''] * pwlength
            for rank in range(0, slots):
                for position in range(0, pwlength):
                    top_char = ''
                    for char in list(self[pwlength].keys()):
                        if (self[pwlength][char][position] >= freq) and ( char not in processed_values[pwlength] and (char not in ranked_values)):
                            logging.debug('Length: {} -> Rank: {} -> Current char: {} at Frequency: {} processed chars for position {}: {}'.format(pwlength, rank+1, char, freq, position, processed_values[pwlength]))
                            freq = self[pwlength][char][position]
                            top_char = char
                    processed_values[pwlength][position] = top_char
                    logging.debug('Length: {} -> Processed {} at position {} for rank {}'.format(pwlength, top_char, position, rank+1))
                    row[pwlength][rank][position] = (top_char, freq)
                    freq = 0
                ranked_values += processed_values[pwlength]
                logging.debug('Length: {} Current row for rank {}: {}'.format(pwlength, rank+1, row[pwlength][rank]))
                logging.debug('Length: {} Rank: {} Currently ranked values: {}'.format(pwlength, rank+1, ranked_values))
                logging.debug('Length {} completed: {}'.format(pwlength, row[pwlength]))
        self.result = row
        return row 
     
    def mask(self):
        #final = {}
        for length in list(self.result.keys()):
            mask = {}
            for rank, row in enumerate(self.result[length]):
                #print('[*] Rank {}: {}'.format(rank+1, row))
                mask[rank+1] = [ self.char_to_mask(char) for char, freq in row ]
                print('{}'.format(''.join(mask[rank+1]))) 
            #final[length] = mask
                
    '''
        output = set()
        if len(list(self.result.keys())) > 0:
            for length in list(self.result.keys()):
                for row in self.result[length]:
                    mask = ''
                    #if 0 not in [j for i,j in row ]:  
                    for values in row:
                        mask += self.char_to_mask(values[0])
                    output.add(mask)
        my_list = list(output)
        my_list.sort( key = len )
        for item in my_list:
            print(item) 
    '''   

    def keyspace(self):
        ''' 
        This doesn't work atm...
        '''
        output = {}
        if len(list(self.result.keys())) > 0:
            for length in list(self.result.keys()):
                for row in self.result[length]:
                    pos = 1
                    if 0 not in [j for i,j in row ]:
                        for values in row:
                            charset.add(values[0])
                            output[pos] = charset
                            pos += 1 
     
    def csv(self):
        import csv
        import io
        if len(list(self.result.keys())) > 0:
            header = [ 'Length', 'Rank', 'Position', 'Char', 'Freq', 'Mask' ]
            output= io.StringIO()
            wr = csv.writer(output, delimiter=',', quoting=csv.QUOTE_ALL)
            wr.writerow( header )
            for length in list(self.result.keys()):
                rank = 1
                for row in self.result[length]:
                    pos = 1
                    vals = ''
                    for values in row:
                        wr.writerow( [ length, rank, pos, values[0], values[1], self.char_to_mask(values[0]) ] )
                        pos += 1
                    rank += 1
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
        for length in list(self.result.keys()):
            print('[*] Character frequency analysis completed for length: {}, Passwords: {}'.format(length, self.stats[length])) 
            for row in self.result[length]:
                print('[*] Rank {}: {}'.format(rank, row))
                rank += 1
            rank = 1 

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

