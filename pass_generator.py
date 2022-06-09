import string   # Importing this module instead of typing each character manually.
import secrets  # Using secrets instead of random because it is safer.


def password_generator():
    print("Password generator!")
    # Password generator. 0 =  off, 1 = on
    print("Length, lower, upper, numbers, symbols")
    print("Example: '20, 1, 1, 0, 1' - Generates 20 char password without numbers.")
    # taking five inputs at a time
    try:
        length, lower, upper, number, symbol = input("Enter five values: ").split(',')
        print("-" * 30)
        generated_password = pw_generator(int(length), int(lower), int(upper), int(number), int(symbol))
        print("Generated pw: " + generated_password)
        print("-" * 30)
        return generated_password
    except (ValueError, TypeError) as err:
        print("-" * 30)
        print(f"Error: '{err}'")
        print("-" * 30)


def pw_generator(pass_length, lower=1, upper=1, numbers=1, symbols=1):
    lower_list = string.ascii_lowercase
    upper_list = string.ascii_uppercase
    number_list = string.digits
    symbol_list = string.punctuation

    password = ""

    if lower == 1:
        password += lower_list
    if upper == 1:
        password += upper_list
    if numbers == 1:
        password += number_list
    if symbols == 1:
        password += symbol_list

    return ''.join(secrets.choice(password) for i in range(pass_length))
