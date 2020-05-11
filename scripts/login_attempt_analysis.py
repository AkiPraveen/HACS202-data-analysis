# Data Analysis Code II
# Akilesh Praveen
# HACS202

import re

# debug boolean
debug = False

def main():
    data = []

    with open('logins/101.txt', 'r') as fp:

        line = fp.readline()
        while line:
            line_data = re.search("([0-9]{4}-[0-9]{2}-[0-9]{2})\s([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]*;(.*);password;(.*);(.*)", line)

            if line_data:
                my_date = line_data.group(1)
                my_time = line_data.group(2)
                my_ip = line_data.group(3)
                my_user = line_data.group(4)
                my_password = line_data.group(5)

                data.append([my_date, my_time, my_ip, my_user, my_password])

            else:
                print("---")
                print("error parsing an event.")
                print("event -> ", line)
                print("---")

            line = fp.readline()

    if debug:
        print(data)


if __name__ == "__main__":
    main()