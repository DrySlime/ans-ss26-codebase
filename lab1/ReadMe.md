# Hey quick and dirty notepad here.

We have multiple files.

## packet_debugger.py
Thats just a debugger i let gemini create. Its giving us some info out on the terminal.

## ans_controller.py
Thats just our main controller

## ans_router.py ans_switch.py
the logic for switch and router in 2 files for clean coding practice. especially if we want to reuse this code in a later Lab 

## run_network.py
Here you find our network topology


# CLI Instructions 
to run controller:
ryu-manager ans_controller.py

to run mininet:
sudo python3 run_network.py

to clear mininet:
sudo mn -c