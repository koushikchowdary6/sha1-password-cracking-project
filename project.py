import hashlib
import time
import sys
import itertools
from multiprocessing import Pool, cpu_count

# --- Configuration ---
PASSWORD_FILE = 'passwords.txt'
DICTIONARY_FILE = 'dictionary.txt'

# Configuration - adjust these values based on the expected password complexity
MAX_DIGIT_LEN = 8
MAX_APPEND_DIGITS = 10000  # Increased from 1000
COMMON_YEARS = list(range(1980, 2025))  # Common years people use in passwords
COMMON_SEPARATORS = ['', '.', '_', '-']  # Common separators between words/numbers
MAX_WORD_COMBINATIONS = 2  # Try combinations of dictionary words

# --- Helper Functions ---

def load_passwords(filename):
    """Loads passwords from the file into a dictionary {hash: user_id}."""
    hashes = {}
    print(f"[*] Loading passwords from '{filename}'...")
    try:
        with open(filename, 'r') as f:
            for line_num, line in enumerate(f, 1):
                parts = line.strip().split()
                if len(parts) == 2:
                    user_id, hash_val = parts
                    # Store hash in lowercase for consistent comparison
                    hashes[hash_val.lower()] = user_id
                else:
                    print(f"[!] Warning: Skipping malformed line {line_num} in {filename}: {line.strip()}")
    except FileNotFoundError:
        print(f"[!] Error: Password file '{filename}' not found. Exiting.")
        sys.exit(1)
    print(f"[*] Loaded {len(hashes)} target hashes.")
    return hashes

def load_dictionary(filename):
    """Loads words from the dictionary file into a list."""
    words = []
    print(f"[*] Loading dictionary from '{filename}'...")
    try:
        with open(filename, 'r') as f:
            for line in f:
                # Assuming dictionary words are already lowercase and stripped
                word = line.strip()
                if word:  # Avoid empty lines
                    words.append(word)
    except FileNotFoundError:
        print(f"[!] Error: Dictionary file '{filename}' not found. Exiting.")
        sys.exit(1)
    print(f"[*] Loaded {len(words)} words from dictionary.")
    return words

def calculate_sha1(text):
    """Calculates the SHA-1 hash of a given string."""
    return hashlib.sha1(text.encode('utf-8')).hexdigest().lower()

def save_results(cracked_passwords):
    """Save cracked passwords to a file."""
    with open('cracked_passwords.txt', 'w') as f:
        for user_id in sorted(cracked_passwords.keys(), key=lambda x: int(x) if x.isdigit() else x):
            f.write(f"{user_id} {cracked_passwords[user_id]}\n")
    print(f"[*] Results saved to cracked_passwords.txt")

# --- Advanced Cracking Strategies ---

def try_pure_digits(remaining_hashes):
    """Try passwords consisting only of digits."""
    cracked = {}
    
    for length in range(1, MAX_DIGIT_LEN + 1):
        print(f"[*] Checking digits of length {length}...")
        limit = 10**length
        
        # For longer lengths, use a more efficient approach
        if length >= 7:
            for i in range(limit):
                candidate_password = f"{i:0{length}d}"
                candidate_hash = calculate_sha1(candidate_password)
                
                if candidate_hash in remaining_hashes:
                    user_id = remaining_hashes[candidate_hash]
                    print(f"[+] SUCCESS! User {user_id}: {candidate_password}")
                    cracked[user_id] = candidate_password
        else:
            # For shorter lengths, pre-generate all possible passwords
            candidates = [f"{i:0{length}d}" for i in range(limit)]
            
            for candidate_password in candidates:
                candidate_hash = calculate_sha1(candidate_password)
                
                if candidate_hash in remaining_hashes:
                    user_id = remaining_hashes[candidate_hash]
                    print(f"[+] SUCCESS! User {user_id}: {candidate_password}")
                    cracked[user_id] = candidate_password
    
    return cracked

def try_common_dates(remaining_hashes):
    """Try common date formats as passwords."""
    cracked = {}
    date_formats = []
    
    # Common date formats (YYYYMMDD, DDMMYYYY, etc.)
    for year in range(1950, 2025):
        for month in range(1, 13):
            for day in range(1, 32):
                date_formats.append(f"{year}{month:02d}{day:02d}")  # YYYYMMDD
                date_formats.append(f"{day:02d}{month:02d}{year}")  # DDMMYYYY
                date_formats.append(f"{month:02d}{day:02d}{year}")  # MMDDYYYY
    
    print(f"[*] Trying {len(date_formats)} common date formats...")
    for date in date_formats:
        candidate_hash = calculate_sha1(date)
        if candidate_hash in remaining_hashes:
            user_id = remaining_hashes[candidate_hash]
            print(f"[+] SUCCESS! User {user_id}: {date}")
            cracked[user_id] = date
    
    return cracked

def try_dictionary_words(remaining_hashes, dictionary):
    """Try single dictionary words as passwords."""
    cracked = {}
    
    print(f"[*] Checking {len(dictionary)} dictionary words...")
    for word in dictionary:
        candidate_hash = calculate_sha1(word)
        
        if candidate_hash in remaining_hashes:
            user_id = remaining_hashes[candidate_hash]
            print(f"[+] SUCCESS! User {user_id}: {word}")
            cracked[user_id] = word
    
    return cracked

def try_words_with_transformations(remaining_hashes, dictionary):
    """Try dictionary words with common transformations."""
    cracked = {}
    
    # Create some common transformations
    transformations = [
        lambda w: w.capitalize(),                  # First letter capitalized
        lambda w: w.upper(),                       # All uppercase
        lambda w: w[::-1],                         # Reversed
        lambda w: w + w,                           # Repeated (e.g., catcat)
        lambda w: "".join(c for c in w if c.isalnum())  # Strip non-alphanumeric
    ]
    
    print(f"[*] Applying {len(transformations)} transformations to dictionary words...")
    for word in dictionary:
        for transform in transformations:
            try:
                transformed_word = transform(word)
                candidate_hash = calculate_sha1(transformed_word)
                
                if candidate_hash in remaining_hashes:
                    user_id = remaining_hashes[candidate_hash]
                    print(f"[+] SUCCESS! User {user_id}: {transformed_word}")
                    cracked[user_id] = transformed_word
            except:
                continue  # Skip if transformation fails
    
    return cracked

def try_word_digit_combinations(remaining_hashes, dictionary, pool):
    """Try dictionary words with appended/prepended digits."""
    cracked = {}
    
    # Common numbers to append (0-9999, years, etc.)
    append_numbers = list(range(MAX_APPEND_DIGITS)) + COMMON_YEARS
    
    # Split dictionary into chunks for parallel processing
    dict_chunks = _split_list(dictionary, cpu_count() * 4)
    
    # For each chunk of dictionary words
    print(f"[*] Trying dictionary words with digits using {cpu_count()} processes...")
    
    results = pool.starmap(
        _process_word_digit_chunk,
        [(chunk, remaining_hashes, append_numbers) for chunk in dict_chunks]
    )
    
    # Combine results
    for result in results:
        cracked.update(result)
    
    return cracked

def _process_word_digit_chunk(words_chunk, remaining_hashes, append_numbers):
    """Process a chunk of words with digit combinations."""
    cracked = {}
    
    for word in words_chunk:
        # Try appending numbers
        for num in append_numbers:
            # Try word + number
            candidate = f"{word}{num}"
            candidate_hash = calculate_sha1(candidate)
            
            if candidate_hash in remaining_hashes:
                user_id = remaining_hashes[candidate_hash]
                print(f"[+] SUCCESS! User {user_id}: {candidate}")
                cracked[user_id] = candidate
            
            # Try number + word
            candidate = f"{num}{word}"
            candidate_hash = calculate_sha1(candidate)
            
            if candidate_hash in remaining_hashes:
                user_id = remaining_hashes[candidate_hash]
                print(f"[+] SUCCESS! User {user_id}: {candidate}")
                cracked[user_id] = candidate
            
            # Try with separators
            for sep in COMMON_SEPARATORS:
                candidate = f"{word}{sep}{num}"
                candidate_hash = calculate_sha1(candidate)
                
                if candidate_hash in remaining_hashes:
                    user_id = remaining_hashes[candidate_hash]
                    print(f"[+] SUCCESS! User {user_id}: {candidate}")
                    cracked[user_id] = candidate
    
    return cracked

def try_word_combinations(remaining_hashes, dictionary, pool):
    """Try combinations of dictionary words."""
    cracked = {}
    
    # Get the most common words (first 1000)
    common_words = dictionary[:1000] if len(dictionary) > 1000 else dictionary
    
    # Create word pairs with common separators
    print(f"[*] Trying combinations of dictionary words...")
    
    # Split into chunks for parallel processing
    word_pairs = list(itertools.combinations(common_words, 2))
    pair_chunks = _split_list(word_pairs, cpu_count() * 4)
    
    results = pool.starmap(
        _process_word_pair_chunk,
        [(chunk, remaining_hashes, COMMON_SEPARATORS) for chunk in pair_chunks]
    )
    
    # Combine results
    for result in results:
        cracked.update(result)
    
    return cracked

def _process_word_pair_chunk(word_pairs, remaining_hashes, separators):
    """Process a chunk of word pairs."""
    cracked = {}
    
    for word1, word2 in word_pairs:
        for sep in separators:
            # Try word1 + sep + word2
            candidate = f"{word1}{sep}{word2}"
            candidate_hash = calculate_sha1(candidate)
            
            if candidate_hash in remaining_hashes:
                user_id = remaining_hashes[candidate_hash]
                print(f"[+] SUCCESS! User {user_id}: {candidate}")
                cracked[user_id] = candidate
            
            # Try word2 + sep + word1
            candidate = f"{word2}{sep}{word1}"
            candidate_hash = calculate_sha1(candidate)
            
            if candidate_hash in remaining_hashes:
                user_id = remaining_hashes[candidate_hash]
                print(f"[+] SUCCESS! User {user_id}: {candidate}")
                cracked[user_id] = candidate
    
    return cracked

def try_leetspeak(remaining_hashes, dictionary):
    """Try leetspeak transformations of dictionary words."""
    cracked = {}
    
    # Basic leetspeak transformations
    leet_map = {
        'a': ['4', '@'],
        'e': ['3'],
        'i': ['1', '!'],
        'o': ['0'],
        's': ['5', '$'],
        't': ['7'],
        'l': ['1'],
        'z': ['2']
    }
    
    print(f"[*] Applying leetspeak transformations to common words...")
    
    # Only apply to most common words to save time
    common_words = dictionary[:500] if len(dictionary) > 500 else dictionary
    
    for word in common_words:
        # Try basic full replacements
        for char, replacements in leet_map.items():
            if char in word:
                for replacement in replacements:
                    leetword = word.replace(char, replacement)
                    candidate_hash = calculate_sha1(leetword)
                    
                    if candidate_hash in remaining_hashes:
                        user_id = remaining_hashes[candidate_hash]
                        print(f"[+] SUCCESS! User {user_id}: {leetword}")
                        cracked[user_id] = leetword
    
    return cracked

def _split_list(lst, n):
    """Split list into n chunks for parallel processing."""
    k, m = divmod(len(lst), n)
    return [lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]

# --- Main Cracking Logic ---

def main():
    start_time = time.time()
    
    target_hashes = load_passwords(PASSWORD_FILE)
    dictionary = load_dictionary(DICTIONARY_FILE)
    
    # Keep track of cracked passwords and remaining hashes
    all_cracked = {}
    remaining_hashes = target_hashes.copy()
    
    # Create a multiprocessing pool for parallel tasks
    with Pool(processes=cpu_count()) as pool:
        # Strategy 1: Pure Digits
        print("\n--- Running Strategy 1: Pure Digits ---")
        cracked = try_pure_digits(remaining_hashes)
        all_cracked.update(cracked)
        print(f"[*] Strategy 1 found {len(cracked)} passwords.")
        
        # Update remaining hashes
        for user_id, password in cracked.items():
            hash_val = calculate_sha1(password)
            if hash_val in remaining_hashes:
                del remaining_hashes[hash_val]
        print(f"[*] Hashes remaining: {len(remaining_hashes)}")
        
        # Strategy 2: Common Dates
        if remaining_hashes:
            print("\n--- Running Strategy 2: Common Date Formats ---")
            cracked = try_common_dates(remaining_hashes)
            all_cracked.update(cracked)
            print(f"[*] Strategy 2 found {len(cracked)} passwords.")
            
            # Update remaining hashes
            for user_id, password in cracked.items():
                hash_val = calculate_sha1(password)
                if hash_val in remaining_hashes:
                    del remaining_hashes[hash_val]
            print(f"[*] Hashes remaining: {len(remaining_hashes)}")
        
        # Strategy 3: Dictionary Words
        if remaining_hashes:
            print("\n--- Running Strategy 3: Dictionary Words ---")
            cracked = try_dictionary_words(remaining_hashes, dictionary)
            all_cracked.update(cracked)
            print(f"[*] Strategy 3 found {len(cracked)} passwords.")
            
            # Update remaining hashes
            for user_id, password in cracked.items():
                hash_val = calculate_sha1(password)
                if hash_val in remaining_hashes:
                    del remaining_hashes[hash_val]
            print(f"[*] Hashes remaining: {len(remaining_hashes)}")
        
        # Strategy 4: Dictionary Word Transformations
        if remaining_hashes:
            print("\n--- Running Strategy 4: Dictionary Word Transformations ---")
            cracked = try_words_with_transformations(remaining_hashes, dictionary)
            all_cracked.update(cracked)
            print(f"[*] Strategy 4 found {len(cracked)} passwords.")
            
            # Update remaining hashes
            for user_id, password in cracked.items():
                hash_val = calculate_sha1(password)
                if hash_val in remaining_hashes:
                    del remaining_hashes[hash_val]
            print(f"[*] Hashes remaining: {len(remaining_hashes)}")
        
        # Strategy 5: Word + Digit Combinations
        if remaining_hashes:
            print("\n--- Running Strategy 5: Word + Digit Combinations ---")
            cracked = try_word_digit_combinations(remaining_hashes, dictionary, pool)
            all_cracked.update(cracked)
            print(f"[*] Strategy 5 found {len(cracked)} passwords.")
            
            # Update remaining hashes
            for user_id, password in cracked.items():
                hash_val = calculate_sha1(password)
                if hash_val in remaining_hashes:
                    del remaining_hashes[hash_val]
            print(f"[*] Hashes remaining: {len(remaining_hashes)}")
        
        # Strategy 6: Leetspeak Transformations
        if remaining_hashes:
            print("\n--- Running Strategy 6: Leetspeak Transformations ---")
            cracked = try_leetspeak(remaining_hashes, dictionary)
            all_cracked.update(cracked)
            print(f"[*] Strategy 6 found {len(cracked)} passwords.")
            
            # Update remaining hashes
            for user_id, password in cracked.items():
                hash_val = calculate_sha1(password)
                if hash_val in remaining_hashes:
                    del remaining_hashes[hash_val]
            print(f"[*] Hashes remaining: {len(remaining_hashes)}")
        
        # Strategy 7: Word Combinations (most resource-intensive)
        if remaining_hashes:
            print("\n--- Running Strategy 7: Word Combinations ---")
            cracked = try_word_combinations(remaining_hashes, dictionary, pool)
            all_cracked.update(cracked)
            print(f"[*] Strategy 7 found {len(cracked)} passwords.")
            
            # Update remaining hashes
            for user_id, password in cracked.items():
                hash_val = calculate_sha1(password)
                if hash_val in remaining_hashes:
                    del remaining_hashes[hash_val]
            print(f"[*] Hashes remaining: {len(remaining_hashes)}")
    
    # --- Summary ---
    end_time = time.time()
    print("\n--- Cracking Summary ---")
    print(f"Total time taken: {end_time - start_time:.2f} seconds")
    print(f"Total hashes loaded: {len(target_hashes)}")
    print(f"Total passwords cracked: {len(all_cracked)}")
    print(f"Cracking success rate: {len(all_cracked)/len(target_hashes)*100:.2f}%")
    print(f"Hashes remaining: {len(remaining_hashes)}")
    
    # Print cracked passwords
    if all_cracked:
        print("\n--- Cracked Passwords ---")
        try:
            sorted_user_ids = sorted(all_cracked.keys(), key=int)
        except ValueError:
            sorted_user_ids = sorted(all_cracked.keys())
        
        for user_id in sorted_user_ids:
            print(f"User {user_id}: {all_cracked[user_id]}")
        
        # Save results to file
        save_results(all_cracked)
    else:
        print("\nNo passwords were cracked.")

if __name__ == "__main__":
    main()