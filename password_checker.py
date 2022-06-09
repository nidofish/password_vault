# Python program to check validation of password
# Module of regular expression is used with search()
import re
import string


def password_checker(password_to_check):
    flag = 0
    while True:
        if len(password_to_check) < 8:
            flag = -1
            break
        elif not re.search(f"[{string.ascii_lowercase}]", password_to_check):
            flag = -1
            break
        elif not re.search(f"[{string.ascii_uppercase}]", password_to_check):
            flag = -1
            break
        elif not re.search(f"[{string.digits}]", password_to_check):
            flag = -1
            break
        elif not re.search(f"[{string.punctuation}]", password_to_check):
            flag = -1
            break
        elif re.search("\s", password_to_check):
            flag = -1
            break
        else:
            flag = 0
            # print("Valid Password")
            break

    if flag == -1:
        return False
    else:
        return True
