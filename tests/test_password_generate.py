"""
Unit tests for the password generation and strength checking utility.

This module contains two test classes:
- TestPasswordStrengthChecker: For testing the check_password_strength function.
- TestPasswordGenerator: For testing the generate_password function.
"""
import unittest
import sys
import os
import string

# Adjust the Python path to include the 'src' directory
# This allows importing 'password_generate' from the 'src' directory
# pylint: disable=wrong-import-position
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# pylint: disable=import-error
from src.password_generate import check_password_strength, generate_password


class TestPasswordStrengthChecker(unittest.TestCase):
    """
    Test suite for the check_password_strength function.
    """

    def test_weak_passwords(self):
        """
        Tests various scenarios that should result in a "Weak" password strength.
        This includes empty strings, short passwords, and passwords that don't meet
        the minimum variety of character types.
        """
        self.assertEqual(check_password_strength(""), "Weak",
                         "Empty string should be Weak")
        self.assertEqual(check_password_strength("abc"), "Weak",
                         "Short password 'abc' should be Weak")
        self.assertEqual(check_password_strength("1234567"), "Weak",
                         "Short password '1234567' should be Weak")

        # 8+ chars, one type
        self.assertEqual(check_password_strength("abcdefgh"), "Weak",
                         "8+ chars, 1 type ('abcdefgh') should be Weak")
        self.assertEqual(check_password_strength("12345678"), "Weak",
                         "8+ chars, 1 type ('12345678') should be Weak")
        self.assertEqual(check_password_strength("ABCDEFGH"), "Weak",
                         "8+ chars, 1 type ('ABCDEFGH') should be Weak")
        self.assertEqual(check_password_strength("!!!!!!!!"), "Weak",
                         "8+ chars, 1 type ('!!!!!!!!') should be Weak")
        self.assertEqual(check_password_strength("abcdefghijkl"), "Weak",
                         "12+ chars, 1 type ('abcdefghijkl') should be Weak")

        # 8+ chars, two types
        self.assertEqual(check_password_strength("abcdefg1"), "Weak",
                         "8+ chars, 2 types ('abcdefg1') should be Weak")
        self.assertEqual(check_password_strength("ABCDEFGh"), "Weak",
                         "8+ chars, 2 types ('ABCDEFGh') should be Weak")
        self.assertEqual(check_password_strength("1234567!"), "Weak",
                         "8+ chars, 2 types ('1234567!') should be Weak")

        # 12+ chars, two types
        self.assertEqual(check_password_strength("abcdefghijkl12"), "Weak",
                         "12+ chars, 2 types ('abcdefghijkl12') should be Weak")
        self.assertEqual(check_password_strength("ABCDEFGHIJKLmn"), "Weak",
                         "12+ chars, 2 types ('ABCDEFGHIJKLmn') should be Weak")
        self.assertEqual(check_password_strength("abcdefghijkl!!"), "Weak",
                         "12+ chars, 2 types ('abcdefghijkl!!') should be Weak")

        # Password 12+ chars with three types (but not all four) - should be Weak.
        self.assertEqual(check_password_strength("abcDefGhij12"), "Weak",
                         "12+ chars, 3 types ('abcDefGhij12') should be Weak (lower, upper, digit)")
        self.assertEqual(check_password_strength("abcDefGhij!!"), "Weak",
                         "12+ chars, 3 types ('abcDefGhij!!') should be Weak (lower, upper, symbol)")
        self.assertEqual(check_password_strength("abcdef12345!"), "Weak",
                         "12+ chars, 3 types ('abcdef12345!') should be Weak (lower, digit, symbol)")
        self.assertEqual(check_password_strength("ABCDEF12345!"), "Weak",
                         "12+ chars, 3 types ('ABCDEF12345!') should be Weak (upper, digit, symbol)")

    def test_medium_passwords(self):
        """
        Tests scenarios that should result in a "Medium" password strength.
        This includes passwords of length 8-11 with at least 3 character types.
        """
        self.assertEqual(check_password_strength("abcDefg1"), "Medium",
                         "Length 8, 3 types ('abcDefg1') should be Medium")
        # Length 8, four types (also Medium)
        msg = ("Length 8, 4 types ('abC12#de') should be Medium "
               "(4 types for 8-11 is also Medium)")
        self.assertEqual(check_password_strength("abC12#de"), "Medium", msg)
        self.assertEqual(check_password_strength("abCdeF1!"), "Medium",
                         "Length 8, 4 types ('abCdeF1!') should be Medium")

        self.assertEqual(check_password_strength("abCdeFg12#"), "Medium",
                         "Length 10, 3 types ('abCdeFg12#') should be Medium")

        self.assertEqual(check_password_strength("aBcDeFg12#$"), "Medium",
                         "Length 11, 3 types ('aBcDeFg12#$') should be Medium")

        # Length 8, all four types (also Medium)
        self.assertEqual(check_password_strength("aB1#cdef"), "Medium",
                         "Length 8, 4 types ('aB1#cdef') should be Medium")

        # Length 11, all four types (also Medium)
        self.assertEqual(check_password_strength("aB1#cdefGh!"), "Medium",
                         "Length 11, 4 types ('aB1#cdefGh!') should be Medium")

    def test_strong_passwords(self):
        """
        Tests scenarios that should result in a "Strong" password strength.
        This includes passwords of length 12+ with all four character types.
        """
        self.assertEqual(check_password_strength("aB1#cDefGhij"), "Strong",
                         "Length 12, 4 types ('aB1#cDefGhij') should be Strong")
        self.assertEqual(check_password_strength("aB1#cD!fG@hI"), "Strong",
                         "Length 12, 4 types ('aB1#cD!fG@hI') should be Strong")
        msg_corrected = (
            "Length 12, 4 types ('ABcdef12345!') should be Strong "
            "(Corrected from expecting Weak)"
        )
        self.assertEqual(check_password_strength("ABcdef12345!"), "Strong", msg_corrected)

        msg_15_klmn = "Length 15, 4 types ('aB1#cDefGhijKlmn') should be Strong"
        self.assertEqual(check_password_strength("aB1#cDefGhijKlmn"), "Strong",
                         msg_15_klmn)
        msg_15_sym = "Length 15, 4 types ('aB1#cDefGhijKlm!@') should be Strong"
        self.assertEqual(check_password_strength("aB1#cDefGhijKlm!@"), "Strong",
                         msg_15_sym)


class TestPasswordGenerator(unittest.TestCase):
    """
    Test suite for the generate_password function.
    """
    def _count_char_type(self, password, char_set):
        """
        Helper method to count occurrences of characters from a given set in a password.
        """
        count = 0
        for char in password:
            if char in char_set:
                count += 1
        return count

    # pylint: disable=too-many-arguments,too-many-locals,too-many-branches
    def _assert_char_types_present(self, password, length, use_uppercase=False, num_uppercase=0,
                                   use_lowercase=False, num_lowercase=0,
                                   use_digits=False, num_digits=0,
                                   use_symbols=False, num_symbols=0):
        """
        Helper method to assert password properties: length, minimum character counts,
        and ensure only allowed character types are present.
        """
        self.assertEqual(len(password), length)

        actual_uppercase = self._count_char_type(password, string.ascii_uppercase)
        actual_lowercase = self._count_char_type(password, string.ascii_lowercase)
        actual_digits = self._count_char_type(password, string.digits)
        actual_symbols = self._count_char_type(password, string.punctuation)

        if use_uppercase:
            msg = f"Should contain minimum {num_uppercase} uppercase"
            self.assertGreaterEqual(actual_uppercase, num_uppercase, msg)
        else:
            self.assertEqual(actual_uppercase, 0, "Should contain no uppercase if not selected")

        if use_lowercase:
            msg = f"Should contain minimum {num_lowercase} lowercase"
            self.assertGreaterEqual(actual_lowercase, num_lowercase, msg)
        else:
            self.assertEqual(actual_lowercase, 0, "Should contain no lowercase if not selected")

        if use_digits:
            msg = f"Should contain minimum {num_digits} digits"
            self.assertGreaterEqual(actual_digits, num_digits, msg)
        else:
            self.assertEqual(actual_digits, 0, "Should contain no digits if not selected")

        if use_symbols:
            msg = f"Should contain minimum {num_symbols} symbols"
            self.assertGreaterEqual(actual_symbols, num_symbols, msg)
        else:
            self.assertEqual(actual_symbols, 0, "Should contain no symbols if not selected")

        allowed_chars = ""
        if use_uppercase:
            allowed_chars += string.ascii_uppercase
        if use_lowercase:
            allowed_chars += string.ascii_lowercase
        if use_digits:
            allowed_chars += string.digits
        if use_symbols:
            allowed_chars += string.punctuation

        if allowed_chars:
            for char_in_pass in password:
                msg = f"Char '{char_in_pass}' not allowed. Allowed: '{allowed_chars}'"
                self.assertIn(char_in_pass, allowed_chars, msg)
        elif length > 0:
            self.fail("Password generated but no character types were specified as allowed.")

    def test_basic_generation_all_types(self):
        """
        Tests password generation with all character types enabled and minimum counts specified.
        """
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
        """
        Tests password generation with only lowercase letters enabled.
        """
        password = generate_password(length=10, use_lowercase=True, num_lowercase=10,
                                     use_uppercase=False, num_uppercase=0,
                                     use_digits=False, num_digits=0,
                                     use_symbols=False, num_symbols=0)
        self._assert_char_types_present(password, 10, use_lowercase=True, num_lowercase=10)

    def test_basic_generation_only_uppercase(self):
        """
        Tests password generation with only uppercase letters enabled.
        """
        password = generate_password(length=10, use_uppercase=True, num_uppercase=10,
                                     use_lowercase=False, num_lowercase=0,
                                     use_digits=False, num_digits=0,
                                     use_symbols=False, num_symbols=0)
        self._assert_char_types_present(password, 10, use_uppercase=True, num_uppercase=10)

    def test_basic_generation_only_digits(self):
        """
        Tests password generation with only digits enabled.
        """
        password = generate_password(length=10, use_digits=True, num_digits=10,
                                     use_uppercase=False, num_uppercase=0,
                                     use_lowercase=False, num_lowercase=0,
                                     use_symbols=False, num_symbols=0)
        self._assert_char_types_present(password, 10, use_digits=True, num_digits=10)

    def test_basic_generation_only_symbols(self):
        """
        Tests password generation with only symbols enabled.
        """
        password = generate_password(length=10, use_symbols=True, num_symbols=10,
                                     use_uppercase=False, num_uppercase=0,
                                     use_lowercase=False, num_lowercase=0,
                                     use_digits=False, num_digits=0)
        self._assert_char_types_present(password, 10, use_symbols=True, num_symbols=10)

    def test_length_constraints(self):
        """
        Tests that generated passwords adhere to specified lengths.
        """
        for length_val in [1, 8, 12, 20]:
            password = generate_password(length=length_val,
                                         use_uppercase=True, num_uppercase=0,
                                         use_lowercase=True,
                                         num_lowercase=1 if length_val > 0 else 0,
                                         use_digits=True, num_digits=0,
                                         use_symbols=True, num_symbols=0)
            self.assertEqual(len(password), length_val)

    def test_minimum_character_counts(self):
        """
        Tests that the generated password meets the specified minimum counts
        for each character type.
        """
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
        """
        Tests the scenario where the sum of minimum character counts equals
        the total password length. Ensures exact counts of each character type.
        """
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
        self.assertEqual(self._count_char_type(password, string.ascii_uppercase), 3)
        self.assertEqual(self._count_char_type(password, string.ascii_lowercase), 3)
        self.assertEqual(self._count_char_type(password, string.digits), 2)
        self.assertEqual(self._count_char_type(password, string.punctuation), 2)

    def test_character_pool_only_lowercase_fills_all(self):
        """
        Tests that if only one character type is enabled (e.g., lowercase),
        all characters in the password (including those filling remaining length)
        are of that type.
        """
        password = generate_password(length=12, use_lowercase=True, num_lowercase=2,
                                     use_uppercase=False, num_uppercase=0,
                                     use_digits=False, num_digits=0,
                                     use_symbols=False, num_symbols=0)
        self._assert_char_types_present(password, 12, use_lowercase=True, num_lowercase=2)
        self.assertTrue(all(c in string.ascii_lowercase for c in password),
                        "All characters should be lowercase as it's the only pool")

    def test_character_pool_uppercase_not_guaranteed_but_available(self):
        """
        Tests that if a type (e.g., uppercase) is not guaranteed by a minimum count
        but is available in the pool, it can appear in the generated password.
        This is probabilistic, so multiple passwords are generated.
        """
        passwords = []
        for _ in range(20):
            p = generate_password(length=10,
                                  use_uppercase=True, num_uppercase=0,
                                  use_lowercase=True, num_lowercase=5,
                                  use_digits=False, num_digits=0,
                                  use_symbols=False, num_symbols=0)
            passwords.append(p)

        msg = ("Uppercase should appear in some passwords if available in pool "
               "and num_uppercase=0")
        self.assertTrue(any(self._count_char_type(p, string.ascii_uppercase) > 0 for p in passwords),
                        msg)
        for p_val in passwords:
            self.assertEqual(len(p_val), 10)
            self.assertGreaterEqual(self._count_char_type(p_val, string.ascii_lowercase), 5)
            self.assertTrue(all(c in string.ascii_lowercase + string.ascii_uppercase for c in p_val))

    def test_error_negative_or_zero_length(self):
        """
        Tests that generate_password raises ValueError for zero or negative length.
        """
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
        """
        Tests ValueError if sum of minimum character counts exceeds total length.
        """
        err_msg = (
            "Sum of specified minimum character counts .* "
            "exceeds total password length"
        )
        with self.assertRaisesRegex(ValueError, err_msg):
            generate_password(length=5,
                              use_uppercase=True, num_uppercase=3,
                              use_lowercase=True, num_lowercase=3,
                              use_digits=False, num_digits=0,
                              use_symbols=False, num_symbols=0)

    def test_error_no_pool_for_remainder(self):
        """
        Tests ValueError if characters are needed but no types are selected for the pool.
        """
        err_msg = (
            "Cannot fill remaining password length: No character types were "
            "selected for the pool"
        )
        # Case 1: Min count forces chars, but pool for remainder is empty.
        with self.assertRaisesRegex(ValueError, err_msg):
            generate_password(length=5,
                              use_uppercase=False, num_uppercase=1,
                              use_lowercase=False, num_lowercase=0,
                              use_digits=False, num_digits=0,
                              use_symbols=False, num_symbols=0)

        # Case 2: All minimums 0, all use_X False, but length > 0.
        with self.assertRaisesRegex(ValueError, err_msg):
            generate_password(length=5,
                              use_uppercase=False, num_uppercase=0,
                              use_lowercase=False, num_lowercase=0,
                              use_digits=False, num_digits=0,
                              use_symbols=False, num_symbols=0)


if __name__ == '__main__':
    unittest.main()
