# Password Generator

A Python-based command-line tool for generating strong, random passwords with customizable criteria. This tool ensures that generated passwords meet specified requirements for length and character type composition (uppercase, lowercase, digits, symbols).

## Features

-   **Customizable Length:** Specify the exact length of the password.
-   **Character Type Control:**
    -   Include or exclude uppercase letters (A-Z).
    -   Include or exclude lowercase letters (a-z).
    -   Include or exclude digits (0-9).
    -   Include or exclude symbols (e.g., !@#$%^&*).
-   **Minimum Character Counts:** Define the minimum number of each selected character type to ensure they are present in the password.
-   **Secure Randomness:** Uses the `secrets` module for cryptographically strong random number generation for character selection.
-   **Shuffling:** Ensures that the characters (guaranteed minimums and the remainder) are well-mixed using `random.shuffle`.
-   **Input Validation:** Comprehensive checks for valid inputs (e.g., positive length, sum of minimums not exceeding total length).
-   **User-Friendly CLI:** Interactive prompts to guide the user through password specification.

## Requirements

-   Python 3.x

## How to Run

1.  **Clone the repository or download the `password_generate.py` file.**
    ```bash
    # If you have git installed
    git clone <repository_url>
    cd password-generator-gemini/password-generator/src
    ```
    Or simply navigate to the directory where you've saved `password_generate.py`.

2.  **Open a terminal or command prompt.**

3.  **Navigate to the directory containing `password_generate.py`:**
    ```bash
    cd path/to/password-generator/src
    ```
    For example, if the file is in `c:\Users\Karthik\projects\password-generator-gemini\password-generator\src\`, you would use:
    ```bash
    cd c:\Users\Karthik\projects\password-generator-gemini\password-generator\src\
    ```

4.  **Run the script:**
    ```bash
    python password_generate.py
    ```

5.  **Follow the on-screen prompts** to specify the password length and character criteria.

## How It Works

1.  **Input Collection:** The script first prompts the user for the desired password length.
2.  **Character Criteria:** It then asks whether to include uppercase letters, lowercase letters, digits, and symbols.
3.  **Minimum Counts:** For each included character type, the user specifies a minimum number of occurrences.
4.  **Validation:**
    -   Ensures password length is positive.
    -   Ensures at least one character type is selected.
    -   Ensures the sum of minimum character counts does not exceed the total password length.
5.  **Password Generation (`generate_password` function):**
    -   A list `password_chars` is initialized.
    -   The script adds the guaranteed minimum number of characters for each selected type to `password_chars` using `secrets.choice()` for secure random selection from the respective character sets (e.g., `string.ascii_uppercase`).
    -   A `character_pool_for_remainder` string is built, containing all character types the user chose to include.
    -   The remaining length of the password is filled by randomly selecting characters from `character_pool_for_remainder` using `secrets.choice()`.
    -   Finally, `random.shuffle()` is used to thoroughly mix all characters in `password_chars` to avoid predictable patterns (e.g., all uppercase at the start).
    -   The list of characters is joined to form the final password string.
6.  **Output:** The generated password is displayed to the user.
7.  **Repeat:** The user is asked if they want to generate another password.

## Example Usage (Console Interaction)

```
Welcome to the Random Password Generator!
This tool will help you create strong, random passwords with custom criteria.
------------------------------------------------------------
Enter desired password length (e.g., 12, min 1, rec 8-128): 16

Configure character types for your password:
  Include uppercase letters (A-Z)? (yes/no): yes
  Include lowercase letters (a-z)? (yes/no): yes
  Include digits (0-9)? (yes/no): yes
  Include symbols (e.g., !@#$%)? (yes/no): yes

Specify minimum counts for included character types:
  Minimum number of uppercase letters (A-Z) (e.g., 2, or 0 if no fixed minimum): 3
  Minimum number of lowercase letters (a-z) (e.g., 2, or 0 if no fixed minimum): 3
  Minimum number of digits (0-9) (e.g., 2, or 0 if no fixed minimum): 2
  Minimum number of symbols (e.g., !@#$%) (e.g., 2, or 0 if no fixed minimum): 2

Generated Password: K&p9!wRjS3bA2mYc

Generate another password? (yes/no): no
------------------------------------------------------------
Thank you for using the Random Password Generator! Stay secure!
```