#Instructions on how to execute the program properly:
#Choose a target machine and a router on which you would like to perform this attack.

#First run on the machine of target IP run SpoofDetection.py (as root user) command is: sudo python3 SpoofDetection.py

1) This program will not print anything and will keep running until an attack is detected
2) When the program detects an ARP Spoof attack it will warn the user that the machine is under attack and will print the real mac address that should be on the ARP packet


#After that, run ARPSpoof.py (can only be run from linux machines, (as root user) command is: sudo python3 ARPSpoofer.py
1) Before running open the python file and change the target and host IP variables located in main to the target and host of your choosing. Ideally, target IP should be another machine on your network that you’re trying to attack, and the host IP should be your local network router’s IP.
2) This program has to be run as the root user. 
3) To exit this program press CTRL-C it may require a couple of tries, if it does not exit keep pressing CTRL-C.
4) This program print everything to a file called output.txt not the system out

#As for the test_ARPSpoofer.py run it using the following command: sudo python3 -m unittest test_ARPSpoofer.py





