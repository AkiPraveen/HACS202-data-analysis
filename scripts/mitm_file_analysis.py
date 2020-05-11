# Data Analysis Code
# AKILESH PRAVEEN
# HACS202

import re

# debug boolean
debug = False

def main():
    # open file
    with open('mitm_files/mitm_file102', 'r') as fp:
        # fp is now our file pointer to the mitm data file.

        data = []

        # read the five lines at the top
        line = fp.readline()
        line = fp.readline()
        line = fp.readline()
        line = fp.readline()
        line = fp.readline()

        
        while line:
            curr = analyze_attack(fp)
            if curr is None:
                break
            else:
                data.append(curr)

        print(data)



def analyze_attack(fp):
    line = fp.readline()

    if not line:
        return None

    # read the first line of an attack
    initial = re.search("([0-9]{4}-[0-9]{2}-[0-9]{2})\s([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]{3}\s-\s\[Debug\]\s\[Connection\]\sAttacker\sconnected:\s(.*)\s\|\sClient\sIdentification:\s(.*)", line)

    if initial:
        my_date = initial.group(1)
        my_time = initial.group(2)
        my_ip = initial.group(3)
        my_client = initial.group(4)

        # number of attempts + whether a password was used or not
        my_attempts = 0
        my_passwords = []

        # this attack continues until we find the 'Attacker closed the connection' line
        end = False
        while(not end):
            nextline = fp.readline()
            found_end = re.search("Attacker\sclosed\sthe\sconnection$",nextline)

            if found_end:
                if (debug):
                    print(">> end successfully found")
                    print("---")
                    print("Attack Stats:")
                    print("date: ", my_date)
                    print("time: ", my_time)
                    print("ip: ", my_ip)
                    print("client: ", my_client)
                    print("attempts: ", str(my_attempts))
                    print("passwords used? ", str(my_passwords))
                    print("---")
                end = True
                return [my_date, my_time, my_ip, my_client, my_attempts, my_passwords]

            # this line is not the end, we can get data from it
            
            # check to see if password attempts have increased
            attempt_add = re.search("has\sso\sfar\smade", nextline)

            if attempt_add:
                my_attempts += 1

            password_add = re.search("trying\sto\sauthenticate\swith\s\"(.*)\"", nextline)

            if password_add:
                if password_add.group(1) == "none":
                    my_passwords.append(False)
                else:
                    my_passwords.append(True)

            




    else:
        print("-----------------")
        print("failed to find initial line.")
        print("offending line:")
        print(line)
        print("attempting to read until next attack.")
        print("-----------------")

        read_until_next(fp)
        return ["", "", "", "", "", []]


def read_until_next(fp):
    line = fp.readline()

    while (line):
        nextgroup = re.search("Attacker\sclosed\sthe\sconnection$",line)

        if nextgroup:
            break
        else:
            line = fp.readline()



if __name__ == "__main__":
    main()


        