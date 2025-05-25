import secrets
import string
import random # Added for shuffling

def generate_password(
    length: int,
    use_uppercase: bool, num_uppercase: int,
    use_lowercase: bool, num_lowercase: int,
    use_digits: bool, num_digits: int,
    use_symbols: bool, num_symbols: int
) -> str:
    """
    Generates a random password of a specified length with user-defined
    character type compositions.

    The password generation ensures the minimum specified counts for each
    selected character type. The remaining characters are filled from the pool
    of all selected character types. The `secrets` module is used for
    cryptographically strong random character selection, and `random.shuffle`
    is used to mix the characters.

    Args:
        length: The desired total length of the password.
        use_uppercase: Whether to include uppercase letters.
        num_uppercase: Minimum number of uppercase letters.
        use_lowercase: Whether to include lowercase letters.
        num_lowercase: Minimum number of lowercase letters.
        use_digits: Whether to include digits.
        num_digits: Minimum number of digits.
        use_symbols: Whether to include symbols/punctuation.
        num_symbols: Minimum number of symbols.

    Returns:
        A randomly generated password string.

    Raises:
        ValueError: If length is not positive, if the sum of minimum character
                    counts exceeds the total length, or if no character types
                    are selected for the pool when characters are needed.
    """
    if not isinstance(length, int) or length <= 0:
        raise ValueError("Password length must be a positive integer.")

    current_sum_minimums = num_uppercase + num_lowercase + num_digits + num_symbols
    if current_sum_minimums > length:
        raise ValueError(
            f"Sum of specified minimum character counts ({current_sum_minimums}) "
            f"exceeds total password length ({length})."
        )

    password_chars = []
    character_pool_for_remainder = ""

    # Add guaranteed uppercase characters
    if use_uppercase:
        character_pool_for_remainder += string.ascii_uppercase
        for _ in range(num_uppercase):
            password_chars.append(secrets.choice(string.ascii_uppercase))

    # Add guaranteed lowercase characters
    if use_lowercase:
        character_pool_for_remainder += string.ascii_lowercase
        for _ in range(num_lowercase):
            password_chars.append(secrets.choice(string.ascii_lowercase))

    # Add guaranteed digits
    if use_digits:
        character_pool_for_remainder += string.digits
        for _ in range(num_digits):
            password_chars.append(secrets.choice(string.digits))

    # Add guaranteed symbols
    if use_symbols:
        character_pool_for_remainder += string.punctuation
        for _ in range(num_symbols):
            password_chars.append(secrets.choice(string.punctuation))

    # Fill the remaining length of the password
    remaining_length = length - len(password_chars)

    if remaining_length > 0 and not character_pool_for_remainder:
        # This should be prevented by validation in main() ensuring at least one 'use_X' is true.
        raise ValueError(
            "Cannot fill remaining password length: No character types were selected for the pool, "
            "but additional characters are needed."
        )

    for _ in range(remaining_length):
        password_chars.append(secrets.choice(character_pool_for_remainder))

    # Shuffle the generated password characters to mix them up
    random.shuffle(password_chars)

    return "".join(password_chars) # Corrected line


def check_password_strength(password: str) -> str:
    """
    Checks the strength of a given password based on length and character types.

    Criteria:
    - Weak:
        - Length < 8
        - OR (Length >= 8 AND < 3 character types: uppercase, lowercase, digits, symbols)
    - Medium:
        - 8 <= Length <= 11
        - AND >= 3 character types
    - Strong:
        - Length >= 12
        - AND all 4 character types are present.
    """
    length = len(password)
    has_upper = False
    has_lower = False
    has_digit = False
    has_symbol = False

    for char in password:
        if char in string.ascii_uppercase:
            has_upper = True
        elif char in string.ascii_lowercase:
            has_lower = True
        elif char in string.digits:
            has_digit = True
        elif char in string.punctuation: # string.punctuation covers common symbols
            has_symbol = True

    char_types_count = sum([has_upper, has_lower, has_digit, has_symbol])

    # Criteria from subtask:
    # - Strong: Length 12+ AND all 4 character types.
    # - Medium: Length 8-11 AND >=3 character types.
    # - Weak: Otherwise.

    if length >= 12 and char_types_count == 4:
        return "Strong"
    elif 8 <= length <= 11 and char_types_count >= 3:
        return "Medium"
    else:
        # Weak if:
        # - Length < 8
        # - OR (Length >= 8 AND < 3 character types)
        # - OR (Length >= 12 AND < 4 character types) and not Medium
        # - OR (Length 8-11 AND < 3 character types) and not Medium
        return "Weak"

def main():
    """
    Main function to run the console-based password generator application.
    It handles user interaction, input validation, and calls the password
    generation logic.
    """
    print("Welcome to the Random Password Generator!")
    print("This tool will help you create strong, random passwords with custom criteria.")
    print("-" * 60)

    while True:
        try:
            length_str = input("Enter desired password length (e.g., 12, min 1, rec 8-128): ").strip()
            if not length_str:
                print("Error: Password length cannot be empty. Please enter a number.")
                continue
            length = int(length_str)

            if length <= 0:
                print("Error: Password length must be a positive number (e.g., 1 or greater).")
                continue
            elif length > 128: # Practical upper limit
                print(f"Error: Password length {length} is very large. "
                      "Please choose a length between 1 and 128 for practicality.")
                continue
            else:
                if length < 8:
                    print("Warning: Passwords shorter than 8 characters are generally considered weak, "
                          "even with specific character types.")

                # Loop for character criteria configuration and generation
                while True: # Allows re-trying criteria if there's an issue
                    character_options_config = {
                        "uppercase": {"prompt_name": "uppercase letters (A-Z)", "chars": string.ascii_uppercase, "count": 0, "include": False},
                        "lowercase": {"prompt_name": "lowercase letters (a-z)", "chars": string.ascii_lowercase, "count": 0, "include": False},
                        "digits":    {"prompt_name": "digits (0-9)", "chars": string.digits, "count": 0, "include": False},
                        "symbols":   {"prompt_name": "symbols (e.g., !@#$%)", "chars": string.punctuation, "count": 0, "include": False},
                    }

                    print("\nConfigure character types for your password:")
                    for key, config in character_options_config.items():
                        while True:
                            choice = input(f"  Include {config['prompt_name']}? (yes/no): ").strip().lower()
                            if choice in ['yes', 'y']:
                                config['include'] = True
                                break
                            elif choice in ['no', 'n']:
                                config['include'] = False
                                break
                            print("  Error: Invalid input. Please type 'yes' or 'no'.")

                    if not any(config['include'] for config in character_options_config.values()):
                        print("\nError: You must select at least one character type to include.")
                        print("Please re-configure character types.\n")
                        continue # Restart character criteria configuration

                    print("\nSpecify minimum counts for included character types:")
                    total_specified_minimums = 0
                    valid_counts_so_far = True
                    for key, config in character_options_config.items():
                        if config['include']:
                            while True:
                                try:
                                    num_str = input(f"  Minimum number of {config['prompt_name']} (e.g., 2, or 0 if no fixed minimum): ").strip()
                                    count = int(num_str)
                                    if count < 0:
                                        print("  Error: Number of characters cannot be negative.")
                                    elif count > length:
                                        print(f"  Error: Minimum {config['prompt_name']} ({count}) cannot exceed total password length ({length}).")
                                    else:
                                        config['count'] = count
                                        break # Valid count for this type
                                except ValueError:
                                    print("  Error: Invalid input. Please enter a whole number for the count.")
                            
                            # Check cumulative sum immediately after each count input
                            current_sum_check = sum(opt['count'] for opt in character_options_config.values() if opt['include'])
                            if current_sum_check > length:
                                print(f"\nError: The sum of minimum characters specified so far ({current_sum_check}) "
                                      f"exceeds the total password length ({length}).")
                                print("Please re-enter character type counts.\n")
                                valid_counts_so_far = False
                                break # Break from the for loop over character_options_config
                    
                    if not valid_counts_so_far:
                        continue # Restart character criteria configuration (outer criteria loop)

                    # Final check on total minimums (should be redundant if above check works, but good safeguard)
                    total_specified_minimums = sum(opt['count'] for opt in character_options_config.values())
                    if total_specified_minimums > length:
                        print(f"\nError: The total sum of minimum characters specified ({total_specified_minimums}) "
                              f"exceeds the total password length ({length}).")
                        print("Please re-configure character types and counts.\n")
                        continue # Restart character criteria configuration

                    try:
                        password_str = generate_password( # Renamed to avoid confusion with the module
                            length,
                            use_uppercase=character_options_config["uppercase"]["include"],
                            num_uppercase=character_options_config["uppercase"]["count"],
                            use_lowercase=character_options_config["lowercase"]["include"],
                            num_lowercase=character_options_config["lowercase"]["count"],
                            use_digits=character_options_config["digits"]["include"],
                            num_digits=character_options_config["digits"]["count"],
                            use_symbols=character_options_config["symbols"]["include"],
                            num_symbols=character_options_config["symbols"]["count"]
                        )
                        print(f"\nGenerated Password: {password_str}")
                        strength = check_password_strength(password_str)
                        print(f"Password Strength: {strength}\n")
                        break # Success, exit character criteria loop
                    except ValueError as e:
                        print(f"\nError during password generation: {e}")
                        print("Please review your length and character count specifications and try again.\n")
                        # This will loop back to re-enter criteria for the current length

        except ValueError:
            print("Error: Invalid input. Please enter a whole number for the length.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

        # Option to check strength of an existing password
        while True:
            check_existing_choice = input("Do you want to check the strength of an existing password? (yes/no): ").strip().lower()
            if check_existing_choice in ['yes', 'y']:
                existing_password = input("Enter the password to check: ").strip()
                if not existing_password:
                    print("Password input cannot be empty.")
                else:
                    strength = check_password_strength(existing_password)
                    print(f"Password Strength: {strength}")
                print("-" * 60) # Separator after checking
                break # Exit this small loop and proceed to "generate another"
            elif check_existing_choice in ['no', 'n']:
                break # Exit this small loop and proceed to "generate another"
            else:
                print("Invalid input. Please type 'yes' or 'no'.")
        
        # Ask if user wants to generate another password
        while True:
            another_choice = input("Generate another password? (yes/no): ").strip().lower()
            if another_choice in ['yes', 'y', 'no', 'n']:
                break
            print("Invalid input. Please type 'yes', 'y', 'no', or 'n'.")

        if another_choice in ['no', 'n']:
            break
        print("-" * 60)

    print("-" * 60)
    print("Thank you for using the Random Password Generator! Stay secure!")

if __name__ == "__main__":
    main()
