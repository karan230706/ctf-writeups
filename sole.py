from Crypto.Cipher import AES
from itertools import combinations_with_replacement

def find_solution():
    """
    Find a, b, c, d such that a^4 + b^4 = c^4 + d^4 + 17
    where max(a,b,c,d) < 20000
    """
    
    # We'll use a dictionary to store fourth powers and their corresponding pairs
    fourth_powers = {}
    max_val = 3000
    
    print("Building fourth powers dictionary...")
    
    # Generate all possible sums of two fourth powers
    for i in range(1, max_val):
        for j in range(i, max_val):  # j >= i to avoid duplicates
            sum_fourth = i**4 + j**4
            if sum_fourth not in fourth_powers:
                fourth_powers[sum_fourth] = []
            fourth_powers[sum_fourth].append((i, j))
    
    print(f"Generated {len(fourth_powers)} unique sums")
    print("Searching for solutions...")
    
    # Look for solutions where one sum is 17 more than another
    solutions = []
    
    for sum1, pairs1 in fourth_powers.items():
        sum2 = sum1 - 17
        if sum2 in fourth_powers:
            pairs2 = fourth_powers[sum2]
            
            # We found a^4 + b^4 = c^4 + d^4 + 17
            for a, b in pairs1:
                for c, d in pairs2:
                    if max(a, b, c, d) < max_val:
                        solutions.append((a, b, c, d))
                        print(f"Found solution: a={a}, b={b}, c={c}, d={d}")
                        print(f"Verification: {a}^4 + {b}^4 = {a**4 + b**4}")
                        print(f"             {c}^4 + {d}^4 + 17 = {c**4 + d**4 + 17}")
                        print(f"Key material: a*b*c*d = {a*b*c*d}")
    
    return solutions

def decrypt_flag(a, b, c, d, encrypted_hex):
    """
    Decrypt the flag using the found values
    """
    # Generate the key
    key_material = str(a * b * c * d).zfill(16).encode()
    print(f"Key: {key_material}")
    
    # Decrypt
    cipher = AES.new(key_material, AES.MODE_ECB)
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted = cipher.decrypt(encrypted_bytes)
    
    print(f"Decrypted (raw): {decrypted}")
    print(f"Decrypted (hex): {decrypted.hex()}")
    
    # Try to decode as text
    try:
        flag = decrypted.decode('utf-8').rstrip('\x00')  # Remove null padding
        print(f"Flag: {flag}")
        return flag
    except:
        # If direct decode fails, try removing padding
        try:
            # Remove PKCS7 padding
            pad_len = decrypted[-1]
            flag = decrypted[:-pad_len].decode('utf-8')
            print(f"Flag (after removing padding): {flag}")
            return flag
        except:
            print("Could not decode as UTF-8")
            return None

if __name__ == "__main__":
    encrypted_hex = "41593455378fed8c3bd344827a193bde7ec2044a3f7a3ca6fb77448e9de55155"
    
    print("Starting CTF challenge solver...")
    solutions = find_solution()
    
    if solutions:
        print(f"\nFound {len(solutions)} solution(s)!")
        
        # Try each solution
        for i, (a, b, c, d) in enumerate(solutions):
            print(f"\n--- Trying solution {i+1}: a={a}, b={b}, c={c}, d={d} ---")
            flag = decrypt_flag(a, b, c, d, encrypted_hex)
            if flag and flag.isprintable():
                print(f"SUCCESS! Flag found: {flag}")
                break
    else:
        print("No solutions found!")