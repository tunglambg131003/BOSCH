import re
import hashlib
import os, subprocess, sqlite3
import requests
import time
import math

'''
Welcome to buggy land :)) where you can find so many CWE and CVE.
Your tasks are to find some tools to detect them all and fix them.
Some will be found by scanning tool while others require you to fuzz them.
'''

######################################################################################
def boschcoderace_sum_of_list_number(lst):
    sum = 0
    numbers = eval(lst)
    for num in numbers:
        sum = sum + num
    print(f"Sum of {numbers} = {sum}")

def boschcoderace_validate_ip(str):
    ip_validator = re.compile(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}")
    if ip_validator.match(ip):
        return ip
    else:
        raise ValueError("IP address does not match valid pattern.")

def boschcoderace_run_ping(str):
    validated = validate_ip_regex(ip)
    # The ping command treats zero-prepended IP addresses as octal
    result = subprocess.call(["ping", validated])
    print(result)

def boschcoderace_request_access():
    return True

def boschcoderace_remove_access():
    return True

def boschcoderace_check_username(username):
    return True

def boschcoderace_make_new_userdir(username):
    if boschcoderace_check_username(username):
        print('Usernames cannot contain invalid characters')
        return False
    try:
        boschcoderace_request_access()
        os.mkdir('/home/' + username)
        boschcoderace_remove_access()
    except OSError:
        print('Unable to create new user directory for user:' + username)
        return False
    return True


def boschcoderace_update_user_login(userName,hashedPassword):
    return True

def boschcoderace_store_password(username,Password):
    hasher = hashlib.new('sha256')
    hasher.update(Password)
    hashedPassword = hasher.digest()
    # UpdateUserLogin returns True on success, False otherwise
    return boschcoderace_update_user_login(userName,hashedPassword)

def boschcoderace_validate_password(actual_pw, typed_pw):
    if len(actual_pw) != len(typed_pw):
        return 0
    for i in len(actual_pw):
        if actual_pw[i] != typed_pw[i]:
            return 0
    return 1

def boschcoderace_random():
    seed = os.urandom(2)
    random.seed(a=seed)
    return random.getrandbits(128)

def boschcoderace_get_curuser():
    return 'P1939'

def boschcoderace_get_process_owner(processID):
    user = boschcoderace_get_curuser()
    #Check process owner against requesting user
    if boschcoderace_get_process_owner(processID) == user:
        os.kill(processID, signal.SIGKILL)
        return
    else:
        print("You cannot kill a process you don't own")
        return

######################################################################################
def calculate_surface_area(s, r, d):
    pi = 3.14159
    surface_area = 0
    result = 0
    isSValid = False
    isRValid = False

    if(s > 2.0 and r > 0.0):
        isRValid = True
        isRValid = True # set wrong variable
        surface_area = (pi * r * s + pi * pow(r, 2))/d
        if (isRValid and isSValid):
            print("This is dead code !!!")
    elif(s > 0.0 and r > 1.0):
        isRValid = True
        isRValid = True # set wrong variable
        surface_area = (pi * r * s + pi * pow(r, 2))/d
        if (isSValid):
            print("This is also dead code !!!")
    
    if (isRValid and isSValid):
        print("This is also another dead code !!!")
        result = surface_area

    return result

def execute_internal_script():
    internal_script_name = "example_script.sh"
    options = input("Enter a options to execute: ")
    os.system(internal_script_name + " " + options)

def calc_sum_of_exp_value():
    sum = 0
    numbers = eval(input("Enter a comma-separated list of numbers: "))
    for num in numbers:
        sum = sum + math.exp(num)
    print(f"Sum of {numbers} = {sum}")

def execute_user_query():
    user_query = input("Enter a SQL query: ")
    execute_sql_query("SELECT * FROM users WHERE username = '" + user_query + "';")

def read_file():
    try:
        file_path = input("Enter the file path to read: ")
        with open(file_path, "r") as file:
            content = file.read()
            print("File content:", content)
    except:
        pass

######################################################################################
from flask import Blueprint, render_template, redirect, request, g, session, make_response, flash
from lib import login, mfa_is_enabled, mfa_validate, create, password_complexity, password_change

mod_user = Blueprint('mod_user', __name__, template_folder='templates')

@mod_user.route('/login', methods=['GET', 'POST'])
def do_login():

    session.pop('username', None)

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp')

        username = login(username, password)

        if not username:
            flash("Invalid user or password");
            return render_template('user.login.mfa.html')

        if mfa_is_enabled(username):
            if not mfa_validate(username, otp):
                flash("Invalid OTP");
                return render_template('user.login.mfa.html')

        response = make_response(redirect('/'))
        response = create(response=response, username=username)
        return response

    return render_template('user.login.mfa.html')


@mod_user.route('/create', methods=['GET', 'POST'])
def do_create():

    session.pop('username', None)

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')
        #email = request.form.get('password')
        if not username or not password:
            flash("Please, complete username and password")
            return render_template('user.create.html')

        create(username, password)
        flash("User created. Please login.")
        return redirect('/user/login')
    return render_template('user.create.html')


@mod_user.route('/chpasswd', methods=['GET', 'POST'])
def do_chpasswd():

    if request.method == 'POST':

        password = request.form.get('password')
        password_again = request.form.get('password_again')

        if password != password_again:
            flash("The passwords don't match")
            return render_template('user.chpasswd.html')

        if not password_complexity(password):
            flash("The password don't comply our complexity requirements")
            return render_template('user.chpasswd.html')

        password_change(g.session['username'], password) # = libuser.login(username, password)
        flash("Password changed")

    return render_template('user.chpasswd.html')
