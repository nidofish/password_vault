import config as mydb
import os
import getpass
import mysql.connector as mysql
from mysql.connector import Error
import hashlib
import base64
import cryptography.fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pass_generator
from password_checker import password_checker as pw_check


class Cryption:

    @staticmethod
    def encrypt(clear_str_password):
        # Add a way to salt the clear_str_password here
        new_salt = Cryption.generate_salt()
        salted_password = clear_str_password + new_salt
        # Encode the password
        encoded_salted_password = salted_password.encode()  # encoded_salted_password??

        # Encrypt the message
        # Using the main pass provided by the user to encrypt the password
        f = Fernet(Cryption.get_crypt_key(provided_password))
        encrypted_p = f.encrypt(encoded_salted_password)
        pw_string = encrypted_p.decode()  # Turning the byte object into string object
        return pw_string, new_salt

    @staticmethod
    def decrypt(encrypted_pw, salt):
        decryption_key = Fernet(Cryption.get_crypt_key(provided_password))
        try:
            encrypted_back_to_bytes = encrypted_pw.encode('utf-8')
            decrypted = decryption_key.decrypt(encrypted_back_to_bytes)

            # decode the message with pythons built-in decode function.
            salted_password = decrypted.decode()  # Salted message??

            # Remove the salt here
            # Salt is found in SQL table credential
            original_password = salted_password.replace(salt, '')
            return original_password

        except (cryptography.fernet.InvalidToken, TypeError):
            print(f"Wrong decryption key: {decryption_key}")

    @staticmethod
    def hash_this(string):
        return hashlib.sha256(string.encode('utf-8')).hexdigest()

    @staticmethod
    def generate_salt():
        salt = os.urandom(16)
        token = base64.b64encode(salt).decode('utf-8')  # Turning the salt into a string object
        return token

    @staticmethod
    def get_crypt_key(password_provided):  # This is the input in the form of a string
        # This function creates a bytes object of the provided password,
        # Then it adds a salt created from urandom(16)
        # This generates the key that encrypts and decrypts password stored in mysql
        password = password_provided.encode()  # Convert to bytes object

        salt = b'\x97|\xc9\x06\xbb\x9e\x9b\xa1\xf5\xfd\xe5\x1fP\x07\xfc\x7f'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
        return key


def create_master_user(register_user, register_pass):
    execute_query(dbc_limited, f"INSERT INTO access (m_user, m_pass) "
                               f"VALUES ('{register_user}', '{Cryption.hash_this(register_pass)}')")
    return


# Checking if the inputted master username and password match the corresponding hash in the database.
def validate_master_password(auth_user, auth_pass):
    results = read_query(dbc_limited, f"SELECT m_id, m_user, m_pass "
                                      f"FROM access WHERE m_user = '{auth_user}' "
                                      f"AND m_pass = '{Cryption.hash_this(auth_pass)}'")

    # Creating empty variables to be set in for loop below.
    m_id, m_user, m_pass = 0, "", ""
    print(type(results))
    for row in results:
        m_id += row[0]
        m_user += row[1]
        m_pass += row[2]

    if m_pass == Cryption.hash_this(auth_pass):  # Comparing hashes.
        return m_user, m_id
    else:
        print("Bad login")


def create_db_connection(config):
    connection = None
    try:
        if config == "limited":
            # Opening up the limited connection to the database
            connection = mysql.connect(**mydb.dbConfig_limited)
        elif config == "master":
            # Opening up the master connection to the database
            connection = mysql.connect(**mydb.dbConfig_master)
        # print("MySQL Database connection successful")
    except Error as err:
        print(f"Error: '{err}'")

    return connection


def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        # print("Query successful")
    except Error as err:
        print(f"Error: '{err}'")


def read_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        return results
    except Error as err:
        print(f"Error: '{err}'")


def fetch_credentials(query_data):
    # query_data is the cursor.fetchall() that comes after a query search.
    number_of_returns = 0
    for row in query_data:
        # print(line)
        number_of_returns += 1
        print("c_id = ", row[0])
        # print("m_id = ", row[1])
        print("site = ", row[2])
        print("username = ", row[3])
        # Below the query fetches both these fields, password and salt.
        # Then they are retrieved in clear text after decryption method is called.
        print("password = ", Cryption.decrypt(row[4], row[5]))
        print(line)
    print(line)
    return number_of_returns


def login_register():
    # Would the user like to log in or register?
    # If anything else that register, continue.
    # If register, ask for master username and password.
    # Then send the strings over to function.

    try:
        initial_choice = input("Login or register? \n > ").lower()

        if initial_choice == "register" or initial_choice == "reg":
            register_username = input("Enter a username: ")
            register_password = getpass.getpass("Enter a password: ")
            create_master_user(register_username, register_password)
    except ValueError as err:
        print(f"Error: '{err}'")


def fetch_user_info(master_id):
    def fetch_input_method():
        print("How would you like to search for a user? ")
        print("1, Username")
        print("2, Site")
        choice = int(input("> "))
        print(line)
        return choice

    query_method = fetch_input_method()

    if query_method == 1:
        q_search = str(input("Enter username to look for: "))
        query = (f"SELECT c_id, m_id, site, username, secret, salt "
                 f"FROM credentials WHERE username = '{q_search}' "
                 f"AND m_id = '{master_id}'")

        results = read_query(dbc_master, query)
        fetch_credentials(results)

    elif query_method == 2:
        q_search = str(input("Enter site to look for: "))
        query = (f"SELECT c_id, m_id, site, username, secret, salt "
                 f"FROM credentials WHERE site LIKE '%{q_search}%' "
                 f"AND m_id = '{master_id}'")

        results = read_query(dbc_master, query)
        fetch_credentials(results)
    print(line)


def main():
    # If the master username and password returns True, then unpack the two values,
    # into two separate variables. Will be used later.

    if validate_master_password(provided_user, provided_password):
        master_user, master_id = validate_master_password(provided_user, provided_password)

        print(f"Welcome {provided_user}, this is your password vault!")
        print(line)
        while True:
            print("1, Lookup credentials")
            print("2, Add")
            print("3, Remove")
            print("4, List all credentials")
            print("5, Password Generator")
            print(line)
            try:
                inp = int(input("> "))

                if inp == 0:
                    break
                elif inp == 1:

                    fetch_user_info(master_id)

                    while True:
                        if input("Query new user? y or n: ").lower() == "y":
                            fetch_user_info(master_id)
                        else:
                            break

                elif inp == 2:  # Adding a new user entry to the mysql database
                    s = input("Enter site: ")
                    u = input("Enter username: ")
                    p = input("Enter password: ")
                    # Clear-text password is run through a password checker.
                    # This checks if the password is 8 characters
                    # contains numbers, characters, and symbols.
                    if pw_check(p):
                        # Encrypting the clear-text password and fetching salt from function.
                        # Unpacking the password and corresponding salt.
                        encrypted_pass, db_salt = Cryption.encrypt(p)

                        # Inserts the unpacked strings into the database.
                        query = (f"INSERT INTO credentials (m_id, site, username, secret, salt) "
                                 f"VALUES ({master_id}, '{s}','{u}', '{encrypted_pass}', '{db_salt}')")

                        execute_query(dbc_master, query)
                    else:
                        print("Password is not secure, are you sure you wish to continue? 'yes', 'no', or 'random' "
                              "to generate a random password and continue.")
                        answer = input("> ")
                        if answer == "random":
                            new_pw = pass_generator.pw_generator(50)
                            print(f"Would you like to insert this password? 'yes' or 'no'"
                                  f"\n {new_pw}")
                            answer = input("> ")
                            if answer == "yes":
                                new_pass, db_salt = Cryption.encrypt(new_pw)
                                query = (f"INSERT INTO credentials (m_id, site, username, secret, salt) "
                                         f"VALUES ({master_id}, '{s}','{u}', '{new_pass}', '{db_salt}')")

                                execute_query(dbc_master, query)
                            else:
                                pass

                        elif answer == "yes":
                            encrypted_pass, db_salt = Cryption.encrypt(p)
                            query = (f"INSERT INTO credentials (m_id, site, username, secret, salt) "
                                     f"VALUES ({master_id}, '{s}','{u}', '{encrypted_pass}', '{db_salt}')")

                            execute_query(dbc_master, query)
                        else:
                            pass

                elif inp == 3:
                    # Removing a user entry for the database
                    # The ID will be used to lookup if the entry exist AND
                    # belongs to the logged-in user. Otherwise, no results are found.

                    inp_id = int(input("Enter ID to remove up: "))

                    result = read_query(dbc_master, f"SELECT * FROM credentials WHERE c_id = {inp_id} "
                                                    f"AND m_id = '{master_id}'")

                    # This is functionality to see if any entries are found.
                    # This way, deletion can only take place if an entry is found
                    number_of_entries = fetch_credentials(result)
                    if number_of_entries == 1:

                        answer = input("Are you sure you wish to delete? 'Yes': ").lower()
                        if answer == "yes":
                            execute_query(dbc_master, f"DELETE FROM credentials "
                                                      f"WHERE c_id = {inp_id} AND m_id = {master_id} ")
                    else:
                        print("No results found.")
                        print(line)

                elif inp == 4:
                    print("listing..")
                    result = read_query(dbc_master, f"SELECT * FROM credentials "
                                                    f"WHERE m_id = '{master_id}'")
                    fetch_credentials(result)

                elif inp == 5:
                    # Calls the password generator function within pass_generator.py
                    pass_generator.password_generator()
            except ValueError as err:
                print(line)
                print(f"Error: '{err}'")
                print(line)


line = "-" * 30
dbc_limited = create_db_connection("limited")
dbc_master = create_db_connection("master")

login_register()
print(line)
print("Login:")
provided_user = input("user: ")
provided_password = getpass.getpass("password: ")  # Hiding the master password when typed

if __name__ == "__main__":
    main()

