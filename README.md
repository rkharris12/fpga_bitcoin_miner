# fpga_bitcoin_miner
Stratum mining client with support for CPU and FPGA mining.  FPGA implementation of Sha256d for the Pynq-Z2 board.
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
## Specs
***Sha256d Implementation***<pre>          </pre>***Hashrate***

fpga<pre>                    </pre>40 Mhashes/sec

hashlib<pre>                 </pre>17 khashes/sec

python<pre>                  </pre>67 hashes/sec
