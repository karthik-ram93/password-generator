"""
Random Password Generator with Strength Checker.

This script provides functionalities to generate random passwords based on
user-defined criteria (length, character types) and to check the strength
of a given password.
"""
import secrets
import string
import random # Added for shuffling

# pylint: disable=too-many-arguments
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

    Ensures minimum counts for each selected type. Remaining characters are
    filled from the pool of all selected types. Uses `secrets` for strong
    random selection and `random.shuffle` for mixing.

    Args:
        length: Desired total length.
        use_uppercase: Include uppercase letters.
        num_uppercase: Minimum number of uppercase.
        use_lowercase: Include lowercase letters.
        num_lowercase: Minimum number of lowercase.
        use_digits: Include digits.
        num_digits: Minimum number of digits.
        use_symbols: Include symbols/punctuation.
        num_symbols: Minimum number of symbols.

    Returns:
        A randomly generated password string.

    Raises:
        ValueError: If length is not positive, sum of minimums exceeds length,
                    or no character types selected for pool when needed.
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

    if use_uppercase:
        character_pool_for_remainder += string.ascii_uppercase
        for _ in range(num_uppercase):
            password_chars.append(secrets.choice(string.ascii_uppercase))
    if use_lowercase:
        character_pool_for_remainder += string.ascii_lowercase
        for _ in range(num_lowercase):
            password_chars.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        character_pool_for_remainder += string.digits
        for _ in range(num_digits):
            password_chars.append(secrets.choice(string.digits))
    if use_symbols:
        character_pool_for_remainder += string.punctuation
        for _ in range(num_symbols):
            password_chars.append(secrets.choice(string.punctuation))

    remaining_length = length - len(password_chars)
    if remaining_length > 0 and not character_pool_for_remainder:
        raise ValueError(
            "Cannot fill remaining password length: No character types selected for the pool, "
            "but additional characters are needed."
        )

    for _ in range(remaining_length):
        password_chars.append(secrets.choice(character_pool_for_remainder))

    random.shuffle(password_chars)
    return "".join(password_chars)


def check_password_strength(password: str) -> str:
    """
    Checks the strength of a given password based on length and character types.

    Criteria:
    - Weak: Length < 8 OR (Length >= 8 AND < 3 char types).
    - Medium: 8 <= Length <= 11 AND >= 3 char types.
    - Strong: Length >= 12 AND all 4 char types.
    """
    length = len(password)
    has_upper = any(char in string.ascii_uppercase for char in password)
    has_lower = any(char in string.ascii_lowercase for char in password)
    has_digit = any(char in string.digits for char in password)
    has_symbol = any(char in string.punctuation for char in password)

    char_types_count = sum([has_upper, has_lower, has_digit, has_symbol])

    if length >= 12 and char_types_count == 4:
        return "Strong"
    # R1705: Unnecessary "elif" after "return" changed to "if"
    if 8 <= length <= 11 and char_types_count >= 3:
        return "Medium"
    # Default to Weak for all other cases
    return "Weak"


def _get_character_config(length: int) -> tuple[dict, int] | None:
    """
    Handles user input for configuring character types and minimum counts.

    Args:
        length: The total desired password length.

    Returns:
        A tuple containing the character options config dictionary and the
        total sum of specified minimums, or None if configuration fails.
    """
    character_options_config = {
        "uppercase": {"prompt_name": "uppercase letters (A-Z)", "count": 0, "include": False},
        "lowercase": {"prompt_name": "lowercase letters (a-z)", "count": 0, "include": False},
        "digits":    {"prompt_name": "digits (0-9)", "count": 0, "include": False},
        "symbols":   {"prompt_name": "symbols (e.g., !@#$%)", "count": 0, "include": False},
    }

    print("\nConfigure character types for your password:")
    for _, config in character_options_config.items(): # W0612: Unused key replaced with _
        while True:
            prompt_text = f"  Include {config['prompt_name']}? (yes/no): "
            choice = input(prompt_text).strip().lower()
            if choice in ['yes', 'y']:
                config['include'] = True
                break
            if choice in ['no', 'n']: # R1723: Unnecessary "elif" after "break"
                config['include'] = False
                break
            print("  Error: Invalid input. Please type 'yes' or 'no'.")

    if not any(config['include'] for config in character_options_config.values()):
        print("\nError: You must select at least one character type to include.")
        print("Please re-configure character types.\n")
        return None # Indicate failure

    print("\nSpecify minimum counts for included character types:")
    total_specified_minimums = 0
    for _, config in character_options_config.items(): # W0612: Unused key replaced with _
        if config['include']:
            while True:
                min_prompt = (f"  Minimum number of {config['prompt_name']} "
                              "(e.g., 2, or 0 if no fixed minimum): ")
                num_str = input(min_prompt).strip()
                try:
                    count = int(num_str)
                    if count < 0:
                        print("  Error: Number of characters cannot be negative.")
                    elif count > length:
                        error_msg = (f"  Error: Minimum {config['prompt_name']} ({count}) "
                                     f"cannot exceed total password length ({length}).")
                        print(error_msg)
                    else:
                        config['count'] = count
                        break # Valid count for this type
                except ValueError:
                    print("  Error: Invalid input. Please enter a whole number for the count.")

            current_sum_check = sum(opt['count']
                                    for opt in character_options_config.values() if opt['include'])
            if current_sum_check > length:
                error_msg = (f"\nError: The sum of minimum characters specified so far "
                             f"({current_sum_check}) exceeds total password length ({length}).")
                print(error_msg)
                print("Please re-enter character type counts.\n")
                return None # Indicate failure

    total_specified_minimums = sum(opt['count'] for opt in character_options_config.values())
    # This final check might be redundant if the immediate check above works, but good safeguard.
    if total_specified_minimums > length:
        error_msg = (f"\nError: The total sum of minimum characters specified "
                     f"({total_specified_minimums}) exceeds password length ({length}).")
        print(error_msg)
        print("Please re-configure character types and counts.\n")
        return None # Indicate failure

    return character_options_config, total_specified_minimums

def main():
    """
    Main function to run the console-based password generator application.
    Handles user interaction, input validation, and calls generation logic.
    """
    print("Welcome to the Random Password Generator!")
    print("This tool will help you create strong, random passwords with custom criteria.")
    print("-" * 60)

    while True:
        try:
            length_str = input("Enter desired password length (e.g., 12, min 1, rec 8-128): ")
            length_str = length_str.strip()
            if not length_str:
                print("Error: Password length cannot be empty. Please enter a number.")
                continue
            length = int(length_str)

            if length <= 0:
                print("Error: Password length must be a positive number (e.g., 1 or greater).")
                continue
            # R1724: Unnecessary "elif" after "continue"
            if length > 128: # Practical upper limit
                print(f"Error: Password length {length} is very large. "
                      "Choose 1-128 for practicality.")
                continue
            # R1724: Unnecessary "elif" after "continue"
            if length < 8:
                print("Warning: Passwords shorter than 8 characters are generally considered weak, "
                      "even with specific character types.")

            # Loop for character criteria configuration and generation
            while True: # Allows re-trying criteria if there's an issue
                config_result = _get_character_config(length)
                if config_result is None:
                    continue # Re-prompt for length or character config

                character_options_config, _ = config_result # total_mins not needed here

                try:
                    password_str = generate_password(
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
                    print("Please review your length and character count specifications "
                          "and try again.\n")
                    # This will loop back to re-enter criteria for the current length

        except ValueError: # Catch int() conversion error for length
            print("Error: Invalid input. Please enter a whole number for the length.")
        except Exception as e: # W0718: Catching too general exception
            print(f"An unexpected error occurred: {e}")

        # Option to check strength of an existing password
        while True:
            prompt = "Do you want to check the strength of an existing password? (yes/no): "
            check_existing_choice = input(prompt).strip().lower()
            if check_existing_choice in ['yes', 'y']:
                existing_password = input("Enter the password to check: ").strip()
                if not existing_password:
                    print("Password input cannot be empty.")
                else:
                    strength = check_password_strength(existing_password)
                    print(f"Password Strength: {strength}")
                print("-" * 60) # Separator after checking
                break
            if check_existing_choice in ['no', 'n']: # R1723
                break
            print("Invalid input. Please type 'yes' or 'no'.")

        # Ask if user wants to generate another password
        while True:
            another_prompt = "Generate another password? (yes/no): "
            another_choice = input(another_prompt).strip().lower()
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
