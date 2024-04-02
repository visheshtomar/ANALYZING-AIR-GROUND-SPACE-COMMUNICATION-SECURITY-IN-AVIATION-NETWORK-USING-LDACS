# ANALYZING-AIR-GROUND-SPACE-COMMUNICATION-SECURITY-IN-AVIATION-NETWORK-USING-LDACS
L-band Digital Aeronautical Communication System (LDACS) is a modern communication protocol designed for air traffic management. As aviation communication demands robust security, implementing cryptographic mechanisms is essential to ensure data integrity and confidentiality in LDACS.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
    - [Required Libraries](#required-libraries)
    - [Installing Libraries](#installing-libraries)
- [Running the Implementation](#running-the-implementation)
- [Security Testing](#security-testing)

## Prerequisites

- Python 3.8.10 or newer (exact version: 3.8.10)

Ensure Python is installed on your system. You can download and install Python from [the official Python website](https://www.python.org/downloads/). Once installed, verify you have `pip` (Python package installer):

```
python -m ensurepip --default-pip
```

## Installation

### Required Libraries

To run the provided code files, the following libraries are necessary:

- cryptography
- ipaddress
- logging
- os
- random
- scapy
- socket
- struct
- subprocess
- time
- timeit
- typing
- zlib

### Installing Libraries

Run the script below to automatically install the required libraries:

```python
import subprocess

libraries_to_install = [
    'cryptography',
    'ipaddress',
    'logging',
    'os',
    'random',
    'scapy',
    'socket',
    'struct',
    'subprocess',
    'time',
    'timeit',
    'typing',
    'zlib'
]

for lib in libraries_to_install:
    subprocess.run(["pip", "install", lib])
```

## Running the Implementation

Ensure all provided code files are in the same directory.

1. `receiver_DH.py`: This script sets up a listener and generates the cryptographic key for communication. It's vital to initiate this script first:
```
python receiver_DH.py
```

2. `sender_DH.py`: After the receiver is active, run this script to establish a connection and initiate communication:
```
python sender_DH.py
```
## Security Testing

To test the cryptographic security of the LDACS communication, you can simulate an interception attack using the provided `interceptor.py` file.

Follow these steps to conduct the test:

1. `receiver_DH.py`: As usual, start the receiver script first to set up the listener:
```
python receiver_DH.py
```

2. `interceptor.py`: After the receiver is running, initiate the interceptor script:
```
python interceptor.py
```

3. **Modifying Sender**: Before running the sender, manually change the port number in the `sender_DH.py` code to match the interceptor's port. This will cause the sender to pass data via the interceptor.

4. `sender_DH.py`: With the port number adjusted, run the sender script:
```
python sender_DH.py
```

By following this sequence, the interceptor will attempt to mediate the communication between the sender and receiver. Due to cryptographic security mechanisms in place, the receiver should display an error indicating a digital signature mismatch, highlighting the protective features of the implementation.

