#!/usr/bin/env python
import sys, os
module = "kumod"
load_cmd = "sudo insmod " + module + ".ko"
unload_cmd = "sudo rmmod " + module
log_cmd = "dmesg"
showdev_cmd ="cat /proc/devices"

def handle(choice):
        if not len(choice):
            return
        elif choice == "q":
            print("Bye.")
            exit(0)
        elif choice == "1":
            print("Loading Module \"{}\"".format(load_cmd))
            os.system(load_cmd)
        elif choice == "2":
            print("Unloading Module \"{}\"".format(unload_cmd))
            os.system(unload_cmd)
        elif choice == "3":
            print("Kernel Log \"{}\"".format(unload_cmd))
            os.system(log_cmd)
        elif choice == "4":
            print("Devices \"{}\"".format(showdev_cmd))
            os.system(showdev_cmd)
        else:
            print("ERROR : Unkown choice \"{}\"".format(choice))
        sys.stdout.write("Press Enter to continue.")
        sys.stdin.readline().strip()

def print_menu():
        print("******Menu List*****")
        print("1. Load Module")
        print("2. Unload Modlue")
        print("3. Show Kernel Log")
        print("4. Show Devices")
        print("q. Quit")
        print("")


def main():
        print_menu();
        sys.stdout.write("Please select an option:  ")
        choice = sys.stdin.readline().strip()
        handle(choice)

if __name__ == '__main__':
    while True:
        try:
            main()
        except Exception as e:
            print(e)
