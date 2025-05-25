import unittest
import sys
import os
import string

# Adjust the Python path to include the 'src' directory
# This allows importing 'password_generate' from the 'src' directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.password_generate import check_password_strength, generate_password

class TestPasswordStrengthChecker(unittest.TestCase):

    def test_weak_passwords(self):
        # Empty string
        self.assertEqual(check_password_strength(""), "Weak", "Empty string should be Weak")
        # Less than 8 characters
        self.assertEqual(check_password_strength("abc"), "Weak", "Short password 'abc' should be Weak")
        self.assertEqual(check_password_strength("1234567"), "Weak", "Short password '1234567' should be Weak")
        
        # 8+ chars, one type
        self.assertEqual(check_password_strength("abcdefgh"), "Weak", "8+ chars, 1 type ('abcdefgh') should be Weak")
        self.assertEqual(check_password_strength("12345678"), "Weak", "8+ chars, 1 type ('12345678') should be Weak")
        self.assertEqual(check_password_strength("ABCDEFGH"), "Weak", "8+ chars, 1 type ('ABCDEFGH') should be Weak")
        self.assertEqual(check_password_strength("!!!!!!!!"), "Weak", "8+ chars, 1 type ('!!!!!!!!') should be Weak")
        self.assertEqual(check_password_strength("abcdefghijkl"), "Weak", "12+ chars, 1 type ('abcdefghijkl') should be Weak")

        # 8+ chars, two types
        self.assertEqual(check_password_strength("abcdefg1"), "Weak", "8+ chars, 2 types ('abcdefg1') should be Weak")
        self.assertEqual(check_password_strength("ABCDEFGh"), "Weak", "8+ chars, 2 types ('ABCDEFGh') should be Weak")
        self.assertEqual(check_password_strength("1234567!"), "Weak", "8+ chars, 2 types ('1234567!') should be Weak")
        
        # 12+ chars, two types
        self.assertEqual(check_password_strength("abcdefghijkl12"), "Weak", "12+ chars, 2 types ('abcdefghijkl12') should be Weak")
        self.assertEqual(check_password_strength("ABCDEFGHIJKLmn"), "Weak", "12+ chars, 2 types ('ABCDEFGHIJKLmn') should be Weak")
        self.assertEqual(check_password_strength("abcdefghijkl!!"), "Weak", "12+ chars, 2 types ('abcdefghijkl!!') should be Weak")

        # Password 12+ chars with three types (but not all four) - this should be Weak.
        # Rules: Strong = 12+ AND 4 types. Medium = 8-11 AND 3+ types. Else Weak.
        # So, 12+ and 3 types is Weak.
        self.assertEqual(check_password_strength("abcDefGhij12"), "Weak", "12+ chars, 3 types ('abcDefGhij12') should be Weak (lower, upper, digit)")
        self.assertEqual(check_password_strength("abcDefGhij!!"), "Weak", "12+ chars, 3 types ('abcDefGhij!!') should be Weak (lower, upper, symbol)")
        self.assertEqual(check_password_strength("abcdef12345!"), "Weak", "12+ chars, 3 types ('abcdef12345!') should be Weak (lower, digit, symbol)")
        self.assertEqual(check_password_strength("ABCDEF12345!"), "Weak", "12+ chars, 3 types ('ABCDEF12345!') should be Weak (upper, digit, symbol)")


    def test_medium_passwords(self):
        # Length 8, three types
        self.assertEqual(check_password_strength("abcDefg1"), "Medium", "Length 8, 3 types ('abcDefg1') should be Medium")
        self.assertEqual(check_password_strength("abC12#de"), "Medium", "Length 8, 4 types ('abC12#de') should be Medium (originally 3 types test, but 4 types for 8-11 is also Medium)")
        self.assertEqual(check_password_strength("abCdeF1!"), "Medium", "Length 8, 4 types ('abCdeF1!') should be Medium")


        # Length 10, three types
        self.assertEqual(check_password_strength("abCdeFg12#"), "Medium", "Length 10, 3 types ('abCdeFg12#') should be Medium")
        
        # Length 11, three types
        self.assertEqual(check_password_strength("aBcDeFg12#$"), "Medium", "Length 11, 3 types ('aBcDeFg12#$') should be Medium")

        # Length 8, all four types (also Medium)
        self.assertEqual(check_password_strength("aB1#cdef"), "Medium", "Length 8, 4 types ('aB1#cdef') should be Medium")
        
        # Length 11, all four types (also Medium)
        self.assertEqual(check_password_strength("aB1#cdefGh!"), "Medium", "Length 11, 4 types ('aB1#cdefGh!') should be Medium")


    def test_strong_passwords(self):
        # Length 12, all four types
        self.assertEqual(check_password_strength("aB1#cDefGhij"), "Strong", "Length 12, 4 types ('aB1#cDefGhij') should be Strong")
        self.assertEqual(check_password_strength("aB1#cD!fG@hI"), "Strong", "Length 12, 4 types ('aB1#cD!fG@hI') should be Strong")
        self.assertEqual(check_password_strength("ABcdef12345!"), "Strong", "Length 12, 4 types ('ABcdef12345!') should be Strong (Corrected from expecting Weak)")


        # Length 15, all four types
        self.assertEqual(check_password_strength("aB1#cDefGhijKlmn"), "Strong", "Length 15, 4 types ('aB1#cDefGhijKlmn') should be Strong")
        self.assertEqual(check_password_strength("aB1#cDefGhijKlm!@"), "Strong", "Length 15, 4 types ('aB1#cDefGhijKlm!@') should be Strong")


class TestPasswordGenerator(unittest.TestCase):

    def _count_char_type(self, password, char_set):
        count = 0
        for char in password:
            if char in char_set:
                count += 1
        return count

    def _assert_char_types_present(self, password, length, use_uppercase=False, num_uppercase=0,
                                   use_lowercase=False, num_lowercase=0,
                                   use_digits=False, num_digits=0,
                                   use_symbols=False, num_symbols=0,
                                   check_exact_counts=True): # check_exact_counts is more for specific scenarios
        self.assertEqual(len(password), length)
        
        actual_uppercase = self._count_char_type(password, string.ascii_uppercase)
        actual_lowercase = self._count_char_type(password, string.ascii_lowercase)
        actual_digits = self._count_char_type(password, string.digits)
        actual_symbols = self._count_char_type(password, string.punctuation)

        if use_uppercase:
            self.assertGreaterEqual(actual_uppercase, num_uppercase, f"Should contain minimum {num_uppercase} uppercase")
        else:
             self.assertEqual(actual_uppercase, 0, "Should contain no uppercase if not selected")

        if use_lowercase:
            self.assertGreaterEqual(actual_lowercase, num_lowercase, f"Should contain minimum {num_lowercase} lowercase")
        else:
            self.assertEqual(actual_lowercase, 0, "Should contain no lowercase if not selected")

        if use_digits:
            self.assertGreaterEqual(actual_digits, num_digits, f"Should contain minimum {num_digits} digits")
        else:
            self.assertEqual(actual_digits, 0, "Should contain no digits if not selected")

        if use_symbols:
            self.assertGreaterEqual(actual_symbols, num_symbols, f"Should contain minimum {num_symbols} symbols")
        else:
            self.assertEqual(actual_symbols, 0, "Should contain no symbols if not selected")
            
        # Verify that only allowed characters are present
        allowed_chars = ""
        if use_uppercase: allowed_chars += string.ascii_uppercase
        if use_lowercase: allowed_chars += string.ascii_lowercase
        if use_digits: allowed_chars += string.digits
        if use_symbols: allowed_chars += string.punctuation
        
        # This check is only valid if allowed_chars is not empty. 
        # If all use_X are False, allowed_chars will be empty, but generate_password should raise an error before this.
        if allowed_chars:
            for char in password:
                self.assertIn(char, allowed_chars, f"Character '{char}' not allowed in password. Allowed: '{allowed_chars}'")
        elif length > 0 : # If length > 0 and allowed_chars is empty, it implies an issue or specific error case.
            # This case should ideally be caught by generate_password raising an error.
            # If a password IS generated, it implies a bug if allowed_chars is empty.
            self.fail("Password generated but no character types were specified as allowed.")


    # 1. Basic generation
    def test_basic_generation_all_types(self):
        password = generate_password(length=12,
                                     use_uppercase=True, num_uppercase=1,
                                     use_lowercase=True, num_lowercase=1,
                                     use_digits=True, num_digits=1,
                                     use_symbols=True, num_symbols=1)
        self._assert_char_types_present(password, 12,
                                        use_uppercase=True, num_uppercase=1,
                                        use_lowercase=True, num_lowercase=1,
                                        use_digits=True, num_digits=1,
                                        use_symbols=True, num_symbols=1)

    def test_basic_generation_only_lowercase(self):
        password = generate_password(length=10, use_lowercase=True, num_lowercase=10,
                                     use_uppercase=False, num_uppercase=0,
                                     use_digits=False, num_digits=0,
                                     use_symbols=False, num_symbols=0)
        self._assert_char_types_present(password, 10, use_lowercase=True, num_lowercase=10)

    def test_basic_generation_only_uppercase(self):
        password = generate_password(length=10, use_uppercase=True, num_uppercase=10,
                                     use_lowercase=False, num_lowercase=0,
                                     use_digits=False, num_digits=0,
                                     use_symbols=False, num_symbols=0)
        self._assert_char_types_present(password, 10, use_uppercase=True, num_uppercase=10)

    def test_basic_generation_only_digits(self):
        password = generate_password(length=10, use_digits=True, num_digits=10,
                                     use_uppercase=False, num_uppercase=0,
                                     use_lowercase=False, num_lowercase=0,
                                     use_symbols=False, num_symbols=0)
        self._assert_char_types_present(password, 10, use_digits=True, num_digits=10)

    def test_basic_generation_only_symbols(self):
        password = generate_password(length=10, use_symbols=True, num_symbols=10,
                                     use_uppercase=False, num_uppercase=0,
                                     use_lowercase=False, num_lowercase=0,
                                     use_digits=False, num_digits=0)
        self._assert_char_types_present(password, 10, use_symbols=True, num_symbols=10)

    # 2. Length constraints
    def test_length_constraints(self):
        for length_val in [1, 8, 12, 20]: 
            password = generate_password(length=length_val,
                                         use_uppercase=True, num_uppercase=0, 
                                         use_lowercase=True, num_lowercase=1 if length_val > 0 else 0,
                                         use_digits=True, num_digits=0,
                                         use_symbols=True, num_symbols=0)
            self.assertEqual(len(password), length_val)

    # 3. Minimum character counts
    def test_minimum_character_counts(self):
        password = generate_password(length=15,
                                     use_uppercase=True, num_uppercase=3,
                                     use_lowercase=True, num_lowercase=3,
                                     use_digits=True, num_digits=2,
                                     use_symbols=True, num_symbols=2)
        self._assert_char_types_present(password, 15,
                                        use_uppercase=True, num_uppercase=3,
                                        use_lowercase=True, num_lowercase=3,
                                        use_digits=True, num_digits=2,
                                        use_symbols=True, num_symbols=2)

    def test_minimums_equal_length(self):
        password = generate_password(length=10,
                                     use_uppercase=True, num_uppercase=3,
                                     use_lowercase=True, num_lowercase=3,
                                     use_digits=True, num_digits=2,
                                     use_symbols=True, num_symbols=2)
        self._assert_char_types_present(password, 10,
                                        use_uppercase=True, num_uppercase=3,
                                        use_lowercase=True, num_lowercase=3,
                                        use_digits=True, num_digits=2,
                                        use_symbols=True, num_symbols=2)
        # Check exact counts here as sum of minimums equals length
        self.assertEqual(self._count_char_type(password, string.ascii_uppercase), 3)
        self.assertEqual(self._count_char_type(password, string.ascii_lowercase), 3)
        self.assertEqual(self._count_char_type(password, string.digits), 2)
        self.assertEqual(self._count_char_type(password, string.punctuation), 2)


    # 4. Character pool usage
    def test_character_pool_only_lowercase_fills_all(self):
        password = generate_password(length=12, use_lowercase=True, num_lowercase=2,
                                     use_uppercase=False, num_uppercase=0,
                                     use_digits=False, num_digits=0,
                                     use_symbols=False, num_symbols=0)
        self._assert_char_types_present(password, 12, use_lowercase=True, num_lowercase=2)
        self.assertTrue(all(c in string.ascii_lowercase for c in password), 
                        "All characters should be lowercase as it's the only pool")

    def test_character_pool_uppercase_not_guaranteed_but_available(self):
        passwords = [generate_password(length=10,
                                      use_uppercase=True, num_uppercase=0, 
                                      use_lowercase=True, num_lowercase=5, 
                                      use_digits=False, num_digits=0,
                                      use_symbols=False, num_symbols=0) for _ in range(20)]
        
        self.assertTrue(any(self._count_char_type(p, string.ascii_uppercase) > 0 for p in passwords),
                        "Uppercase should appear in some passwords if available in pool and num_uppercase=0")
        for p in passwords:
            self.assertEqual(len(p), 10)
            self.assertGreaterEqual(self._count_char_type(p, string.ascii_lowercase), 5)
            self.assertTrue(all(c in string.ascii_lowercase + string.ascii_uppercase for c in p))


    # 5. Error handling
    def test_error_negative_or_zero_length(self):
        with self.assertRaisesRegex(ValueError, "Password length must be a positive integer."):
            generate_password(length=0, 
                              use_uppercase=False, num_uppercase=0,
                              use_lowercase=True, num_lowercase=0, 
                              use_digits=False, num_digits=0,
                              use_symbols=False, num_symbols=0)
        with self.assertRaisesRegex(ValueError, "Password length must be a positive integer."):
            generate_password(length=-5,
                              use_uppercase=False, num_uppercase=0,
                              use_lowercase=True, num_lowercase=0, 
                              use_digits=False, num_digits=0,
                              use_symbols=False, num_symbols=0)

    def test_error_minimums_exceed_length(self):
        with self.assertRaisesRegex(ValueError, "Sum of specified minimum character counts .* exceeds total password length"):
            generate_password(length=5,
                              use_uppercase=True, num_uppercase=3,
                              use_lowercase=True, num_lowercase=3, 
                              use_digits=False, num_digits=0,
                              use_symbols=False, num_symbols=0)

    def test_error_no_pool_for_remainder(self):
        # Case 1: num_uppercase=1 will add a char. Then remaining_length = 4. Pool will be empty.
        with self.assertRaisesRegex(ValueError, "Cannot fill remaining password length: No character types were selected for the pool"):
            generate_password(length=5,
                              use_uppercase=False, num_uppercase=1, 
                              use_lowercase=False, num_lowercase=0,
                              use_digits=False, num_digits=0,
                              use_symbols=False, num_symbols=0)

        # Case 2: All minimums are 0, all use_X are False, but length > 0
        with self.assertRaisesRegex(ValueError, "Cannot fill remaining password length: No character types were selected for the pool"):
            generate_password(length=5,
                              use_uppercase=False, num_uppercase=0,
                              use_lowercase=False, num_lowercase=0,
                              use_digits=False, num_digits=0,
                              use_symbols=False, num_symbols=0)


if __name__ == '__main__':
    unittest.main()
