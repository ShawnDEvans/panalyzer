#! /usr/bin/env python3
import sys, time, os, operator
import logging
import numpy as np

class CharClass:
    __slots__ = ('length', 'data')
    def __init__(self, length):
        self.length = length
        self.data = np.zeros((length, 128), dtype=np.int32)

class Matrix(dict):
    def __init__(self, min_len=5, max_len=20, infile=None, verbose=False):
        log_fmt = '[*] %(message)s'
        level = logging.DEBUG if verbose >= 2 else (logging.INFO if verbose == 1 else logging.ERROR)
        logging.basicConfig(format=log_fmt, level=level)

        self.result = {}
        self.stats = {}
        self.mymask = []
        self.pass_matrix = {}

        for length in range(min_len, max_len + 1):
            cc = CharClass(length)
            self[length] = cc
            self.pass_matrix[length] = cc

        if infile:
            start = time.time()
            total = 0

            # Read entire file as binary data
            with open(infile.name, 'rb') as f:
                data = f.read()

            # Map file into a 1D NumPy byte array
            arr = np.frombuffer(data, dtype=np.uint8)
            nl = np.flatnonzero(arr == 10)  # Find all newline positions (ASCII 10)

            total_lines = len(nl) + 1
            logging.info(f"Loaded {total_lines} lines as bytes")

            # Vectorized calculation of start and end indices of every line
            starts = np.zeros(total_lines, dtype=np.int64)
            starts[1:] = nl + 1

            ends = np.empty(total_lines, dtype=np.int64)
            ends[:-1] = nl
            ends[-1] = len(arr)

            lengths = ends - starts

            # Process group by length completely vectorized
            for length in range(min_len, max_len + 1):
                mask = (lengths == length)
                L_starts = starts[mask]
                num_lines = len(L_starts)

                if num_lines == 0:
                    continue

                self.stats[length] = num_lines
                total += num_lines

                matrix = self.pass_matrix[length]

                # Column-by-column global extraction and character binning
                for position in range(length):
                    column_data = arr[L_starts + position]
                    counts = np.bincount(column_data, minlength=128)[:128]

                    # ignore control chars (<32) and DEL (127)
                    counts[:32] = 0
                    counts[127] = 0
                    matrix.data[position, :] = counts

            self._vectorization_used = True
            elapsed = time.time() - start
            logging.info(f"VECTORIZED: {total} passwords in {elapsed:.2f}s")

    def _get_top_k(self, row, k=5):
        total = int(row.sum())
        if total == 0:
            return []

        if k >= 128:
            idx = np.argsort(row)[::-1]
        else:
            idx = np.argpartition(row, -k)[-k:]
            idx = idx[np.argsort(row[idx])[::-1]]

        return [
            (int(row[i]), chr(i), round(int(row[i]) / total, 4))
            for i in idx if row[i] > 0
        ]

    def summary(self, slots=10):
        self.result = {}
        for pwlength in sorted(self.pass_matrix.keys()):
            matrix = self.pass_matrix[pwlength]
            processed_values = []
            for position in range(pwlength):
                top_chars = self._get_top_k(matrix.data[position, :], k=slots)
                processed_values.append(top_chars)
            self.result[pwlength] = processed_values

        total_passwords = sum(self.stats.values()) if self.stats else 0

        for pwlength in sorted(self.result.keys()):
            count = self.stats.get(pwlength, 0)
            pct = round((count / total_passwords) * 100, 2) if total_passwords > 0 else 0
            logging.info('Summary for length: {} ({}%)'.format(pwlength, pct))

        return True

    def mask(self, cust=False):
        if not self.result:
            self.summary()
        final_masks = []
        for length in sorted(self.result.keys()):
            pos_data_list = self.result[length]
            if not pos_data_list or not pos_data_list[0]:
                continue
            max_ranks = min(len(p_list) for p_list in pos_data_list if p_list) if any(pos_data_list) else 0
            for rank_idx in range(max_ranks):
                mask_chars = []
                valid_rank = True
                for pos_data in pos_data_list:
                    if rank_idx < len(pos_data):
                        _, char, _ = pos_data[rank_idx]
                        mask_chars.append(self.char_to_mask(char))
                    else:
                        valid_rank = False
                        break
                if valid_rank:
                    final_masks.append((length, "".join(mask_chars)))
        uniq_mask_list = sorted(set(m[1] for m in final_masks), key=len)
        self.mymask = uniq_mask_list
        if not cust:
            print("\n".join(uniq_mask_list))
        return uniq_mask_list

    def keyspace(self):
        if not self.result:
            self.summary()
        for length in sorted(self.result.keys()):
            pos_data_list = self.result[length]
            if not pos_data_list or not pos_data_list[0]:
                continue
            max_ranks = min(len(p_list) for p_list in pos_data_list if p_list) if any(pos_data_list) else 0

            all_chars = set()
            for pos_data in pos_data_list:
                for _, char, _ in pos_data:
                    all_chars.add(char)
            if not all_chars:
                continue

            c_lower = [c for c in all_chars if self.char_to_mask(c) == '?l']
            c_upper = [c for c in all_chars if self.char_to_mask(c) == '?u']
            c_digit = [c for c in all_chars if self.char_to_mask(c) == '?d']
            c_spec  = [c for c in all_chars if c not in c_lower + c_upper + c_digit]
            charset_def = '{},{},{},{}'.format(
                ''.join(sorted(c_lower)),
                ''.join(sorted(c_upper)),
                ''.join(sorted(c_digit)),
                ''.join(sorted(c_spec))
            )

            for rank_idx in range(max_ranks):
                mask_chars = []
                valid_rank = True
                for pos_data in pos_data_list:
                    if rank_idx < len(pos_data):
                        _, char, _ = pos_data[rank_idx]
                        mask_chars.append(self.char_to_mask(char))
                    else:
                        valid_rank = False
                        break
                if valid_rank:
                    print(f"{charset_def},{"".join(mask_chars)}")

    def csv(self):
        import csv, io
        if not self.result:
            self.summary()
        output = io.StringIO()
        writer = csv.writer(output, delimiter=',', quoting=csv.QUOTE_ALL)
        writer.writerow(['Length', 'Rank', 'Position', 'Char', 'Freq'])
        for length in sorted(self.result.keys()):
            for pos_idx, pos_data in enumerate(self.result[length]):
                for rank_idx, (freq, char, _) in enumerate(pos_data):
                    writer.writerow([length, rank_idx + 1, pos_idx + 1, char, freq])
        print(output.getvalue())

    def to_string(self):
        total = sum(self.stats.values()) if self.stats else 0
        if total == 0:
            return
        most_common = max(self.stats.items(), key=operator.itemgetter(1))
        weighted_sum = sum(l * c for l, c in self.stats.items())
        avg_len = weighted_sum / total
        print('[*] Total passwords analyzed: {}'.format(total))
        print('[*] Average password length: {:.2f}'.format(avg_len))
        print('[*] Most common password length: {} ({} or {}%)'.format(
            most_common[0], most_common[1],
            round((most_common[1] / float(total)) * 100, 2)))

    def show_rank(self):
        if not self.result:
            self.summary()
        total = sum(self.stats.values()) if self.stats else 0
        for length in sorted(self.result.keys()):
            count = self.stats.get(length, 0)
            pct = round((count / total) * 100, 2) if total > 0 else 0
            print('[*] Character frequency analysis completed for length: {}, Passwords: {} ({}%)'.format(
                length, count, pct))
            for pos_idx, pos_data in enumerate(self.result[length]):
                if pos_data:
                    top5 = pos_data[:5]
                    parts = ['{}({})'.format(char, freq) for freq, char, _ in top5]
                    print('[*] Position {}: {}'.format(pos_idx + 1, ' | '.join(parts)))

    def char_to_mask(self, char):
        code = ord(char)
        if 65 <= code <= 90: return '?u'
        elif 97 <= code <= 122: return '?l'
        elif 48 <= code <= 57: return '?d'
        else: return '?s'
