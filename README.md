# fpga_bitcoin_miner
Stratum Bitcoin mining client with support for CPU and FPGA mining.  FPGA implementation of Sha256d for the Pynq-Z2 board.
## Requirements
Standard Python modules

Pynq-Z2 board - https://www.tul.com.tw/productspynq-z2.html
## Tool versions
Xilinx Vivado 2019.1

Python 3.6.5
## Instructions
Copy the overlays folder to the same directory as fpgaminer.py to match line 115 of fpgaminer.py

Copy the pynq module located in /usr/local/lib/python3.6/dist-packages/pynq to the same directory as fpgaminer.py

run `python3 fpgaminer.py -h` for command line arguments

To regenerate the Vivado projext, open Vivado, cd to the FPGA directory, and run `source sha256d.tcl` in the TCL command prompt
## Results

FPGA Sha256d:     40 Mhashes/sec

Hashlib Sha256d:  17 khashes/sec

Python Sha256d:   67 hashes/sec
## Credits
I used these repositories as reference for this project.

https://github.com/progranism/Open-Source-FPGA-Bitcoin-Miner

https://github.com/ricmoo/nightminer
