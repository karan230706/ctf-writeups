from decimal import Decimal, getcontext
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import math

# Set very high precision for decimal calculations
getcontext().prec = 150

def solve_mathematical_approach(leak_value, ciphertext_hex):
    """
    Mathematical approach: if we know the decimal part, we can work backwards
    """
    print(f"Mathematical approach for leak = {leak_value}")
    
    ct_bytes = bytes.fromhex(ciphertext_hex)
    leak_str = str(leak_value)
    
    # The range for n (integer part of sqrt(K))
    # Since K is in [10^10, 10^11], sqrt(K) is in [10^5, sqrt(10^11)] ≈ [100000, 316227]
    min_n = 100000
    max_n = 316227
    
    print(f"Trying integer parts from {min_n} to {max_n}")
    
    # Convert leak to fractional part
    fractional_str = "0." + leak_str
    fractional = Decimal(fractional_str)
    
    print(f"Looking for sqrt(K) = n + {fractional}")
    print("Starting search...")
    
    candidates = []
    
    for n in range(min_n, max_n + 1):
        if n % 20000 == 0:
            progress = (n - min_n) / (max_n - min_n) * 100
            print(f"Progress: {progress:.1f}% (n = {n})")
        
        # Calculate K = (n + fractional)^2
        n_plus_frac = Decimal(n) + fractional
        k_exact = n_plus_frac * n_plus_frac
        k = int(k_exact)
        
        # Verify this K is in our range
        if not (10**10 <= k <= 10**11):
            continue
        
        # Double-check: does sqrt(k) have the right decimal part?
        sqrt_k = Decimal(k).sqrt()
        sqrt_k_str = str(sqrt_k)
        
        if '.' in sqrt_k_str:
            actual_decimal = sqrt_k_str.split('.')[-1]
            
            # Check if it matches (at least the first part)
            if actual_decimal.startswith(leak_str[:10]):  # Check first 10 digits
                candidates.append((k, n, sqrt_k, actual_decimal))
                print(f"\nCANDIDATE FOUND!")
                print(f"n = {n}, K = {k}")
                print(f"sqrt(K) = {sqrt_k}")
                print(f"Expected decimal: {leak_str}")
                print(f"Actual decimal: {actual_decimal[:50]}...")
                
                # Check if it's an exact match for more digits
                exact_match = True
                min_len = min(len(leak_str), len(actual_decimal))
                for i in range(min_len):
                    if leak_str[i] != actual_decimal[i]:
                        exact_match = False
                        break
                
                if exact_match and len(actual_decimal) >= len(leak_str):
                    print("EXACT MATCH confirmed!")
                
                # Try to decrypt
                try:
                    key = md5(f"{k}".encode()).digest()
                    cipher = AES.new(key, AES.MODE_ECB)
                    decrypted = unpad(cipher.decrypt(ct_bytes), 16)
                    flag = decrypted.decode('utf-8', errors='ignore')
                    print(f"DECRYPTION SUCCESS! FLAG = {flag}")
                    return k, flag
                except Exception as e:
                    print(f"Decryption failed: {e}")
                    print("Continuing search...")
    
    print(f"\nSearch completed. Found {len(candidates)} candidates total.")
    for k, n, sqrt_k, decimal in candidates:
        print(f"K = {k}, n = {n}, decimal = {decimal[:30]}...")
    
    return None, None

def solve_targeted_search(leak_value, ciphertext_hex):
    """
    More targeted search around likely values
    """
    print(f"\nTargeted search approach...")
    
    ct_bytes = bytes.fromhex(ciphertext_hex)
    leak_str = str(leak_value)
    
    # Try to estimate the approximate square root
    # If the decimal part is very long, the integer part is likely close to a round number
    
    # The leak suggests a very precise decimal, so let's try different strategies
    test_ranges = [
        (100000, 120000),
        (150000, 170000), 
        (200000, 220000),
        (250000, 270000),
        (300000, 316227)
    ]
    
    for start_n, end_n in test_ranges:
        print(f"Testing range n = {start_n} to {end_n}")
        
        for n in range(start_n, end_n + 1):
            if n % 5000 == 0:
                print(f"  Testing n = {n}")
            
            # Try with exact fractional part
            fractional_str = "0." + leak_str
            fractional = Decimal(fractional_str)
            
            n_plus_frac = Decimal(n) + fractional
            k = int(n_plus_frac * n_plus_frac)
            
            if not (10**10 <= k <= 10**11):
                continue
            
            sqrt_k = Decimal(k).sqrt()
            sqrt_k_str = str(sqrt_k)
            
            if '.' in sqrt_k_str:
                actual_decimal = sqrt_k_str.split('.')[-1]
                
                if actual_decimal.startswith(leak_str[:15]):  # Check first 15 digits
                    print(f"\nTARGETED MATCH FOUND!")
                    print(f"n = {n}, K = {k}")
                    
                    try:
                        key = md5(f"{k}".encode()).digest()
                        cipher = AES.new(key, AES.MODE_ECB)
                        decrypted = unpad(cipher.decrypt(ct_bytes), 16)
                        flag = decrypted.decode('utf-8', errors='ignore')
                        print(f"SUCCESS! FLAG = {flag}")
                        return k, flag
                    except Exception as e:
                        print(f"Decryption failed: {e}")
    
    return None, None

# Execute the solver
leak_value = 4336282047950153046404
ct_hex = "7863c63a4bb2c782eb67f32928a1deceaee0259d096b192976615fba644558b2ef62e48740f7f28da587846a81697745"

print("Crypto Challenge Solver - Running...")
print("=" * 60)
print(f"Leak: {leak_value}")
print(f"Leak length: {len(str(leak_value))} digits")
print(f"Ciphertext: {ct_hex}")
print()

# Try mathematical approach first
print("Method 1: Mathematical backwards calculation")
k, flag = solve_mathematical_approach(leak_value, ct_hex)

if flag:
    print(f"\n🎉 SOLUTION FOUND! 🎉")
    print(f"K = {k}")
    print(f"FLAG = {flag}")
else:
    print("\nMethod 1 didn't find solution, trying targeted search...")
    k, flag = solve_targeted_search(leak_value, ct_hex)
    
    if flag:
        print(f"\n🎉 SOLUTION FOUND! 🎉")
        print(f"K = {k}")
        print(f"FLAG = {flag}")
    else:
        print("\nNo solution found. The problem might require:")
        print("1. Different precision handling")
        print("2. Alternative decimal extraction method")
        print("3. Expanded search range")