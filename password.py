#! /usr/bin/env
import concurrent.futures
import logging
import sys

class CharClass(dict):
    def __init__(self, pass_length):
        chars = [ chr(x) for x in range(32, 127) ] 
        char_class = { c: [0] * pass_length for c in chars }
        self.update(char_class)

class Matrix(dict):
     
    def __init__(self, min_len=5, max_len=20, infile=None, verbose=False):
        if verbose:
            logFormat = '%(message)s - %(asctime)s - %(levelname)s'
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
            try:
                passwords = infile.readlines()
                with concurrent.futures.ThreadPoolExecutor(10) as executor:
                    zip( passwords, executor.map(self.process, passwords) )
        
            except IOError as e:
                logging.error('[!] Invalid or missing input file...')
                sys.exit()
        
    def process(self, password):
        position = 0 
        try:
            for char in password.strip():
                self[len(password.strip())][char][position] += 1
                position += 1
            self.stats[len(password.strip())] = self.stats[len(password.strip())]+1 if len(password.strip()) in self.stats.keys() else 0 
        except KeyError:
            logging.info('[!] Password exceeded length boundaries: {}'.format(password))
            pass

    def summary(self, slots):
        row = {}
        processed_values = {}
        top_freq = 0
        freq = 0
        
        for pwlength in self.keys():
            ranked_values = [] 
            row[pwlength] = [ [('',0)] * pwlength for x in range(slots) ] 
            processed_values[pwlength] = [''] * pwlength
            for rank in range(0, slots):
                for position in range(0, pwlength):
                    top_char = ''
                    for char in self[pwlength].keys():
                        if (self[pwlength][char][position] >= freq) and ( char not in processed_values[pwlength] and (char not in ranked_values)):
                            #logging.info('Length: {} -> Rank: {} -> Current char: {} at Frequency: {} processed chars for position {}: {}'.format(pwlength, rank+1, char, freq, position, processed_values[pwlength]))
                            freq = self[pwlength][char][position]
                            top_char = char
                    processed_values[pwlength][position] = top_char
                    #logging.info('Length: {} -> Processed {} at position {} for rank {}'.format(pwlength, top_char, position, rank+1))
                    row[pwlength][rank][position] = (top_char, freq)
                    freq = 0
                ranked_values += processed_values[pwlength]
                logging.info('Length: {} Current row for rank {}: {}'.format(pwlength, rank+1, row[pwlength][rank]))
                logging.info('Length: {} Rank: {} Currently ranked values: {}'.format(pwlength, rank+1, ranked_values))
                logging.info('Length {} completed: {}'.format(pwlength, row[pwlength]))
        self.result = row
        return row 
      
    def mask(self):
        output = set()
        if len(self.result.keys()) > 0:
            for length in self.result.keys():
                for row in self.result[length]:
                    mask = ''
                    if 0 not in [j for i,j in row ]:  
                        for values in row:
                            mask += self.char_to_mask(values[0])
                        output.add(mask)
        my_list = list(output)
        my_list.sort( key = len )
        for item in my_list:
            print item 
   
    def keyspace(self):
        ''' 
        This doesn't work atm...
        '''
        output = {}
        if len(self.result.keys()) > 0:
            for length in self.result.keys():
                for row in self.result[length]:
                    pos = 1
                    if 0 not in [j for i,j in row ]:
                        for values in row:
                            charset.add(values[0])
                            output[pos] = charset
                            pos += 1 
     
    def csv(self):
        import csv
        import StringIO
        if len(self.result.keys()) > 0:
            header = [ 'Length', 'Rank', 'Position', 'Char', 'Freq', 'Mask' ]
            output= StringIO.StringIO()
            wr = csv.writer(output, delimiter=',', quoting=csv.QUOTE_ALL)
            wr.writerow( header )
            for length in self.result.keys():
                rank = 1
                for row in self.result[length]:
                    pos = 1
                    vals = ''
                    for values in row:
                        wr.writerow( [ length, rank, pos, values[0], values[1], self.char_to_mask(values[0]) ] )
                        pos += 1
                    rank += 1
            contents = output.getvalue()
            print contents

    def to_string(self):
        rank = 1 
        for length in self.result.keys():
            print '[*] Character frequency analysis completed for length: {}, Passwords: {}'.format(length, self.stats[length]) 
            for row in self.result[length]:
                print '[*] Rank {}: {}'.format(rank, row)
                rank += 1
            rank = 1 


    def char_to_mask(self, char):
        import re
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
            return ''

