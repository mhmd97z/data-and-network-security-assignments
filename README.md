`These assignments were part of my undergrad coursework at Sharif UT.`

## Buffer Overflow Attack
Buffer overflow is a kind of control hijacking attacks that targets for taking over target machine. For more information refer to the [link](https://cs155.stanford.edu/syllabus.html).

Here we have three different vulnerable programs to exploit:
  - ```prog_vuln1``` does not have defensive structures, and the exploitation is performed through commandline arguments.
  - In the ```prog_vuln4```, stack is non-executable, so the attacker should use ROP.
  - ```prog_vuln3``` makes use of canary mechanism in addition to NX feature, and format string is a possibility for the attacker to exploit.

## Crime Attack
If we compress two strings of equal length, the instance having more frequent words would become shorter than the other one. Therefore, compression can serve as a vulnerability.

Here, we have a server available at [this link](https://pacific-anchorage-60533.herokuapp.com/ce442/) setting a cookie in our browser including a ciphertext which our job is to decipher. This cookie is based on a dictionary-based encoding that takes input, the Get parameter.

## Diffie-Hellman MITM Attack
In this attack, attacker comes between a client and a server, and exchanges Diffie-Hellman protocol keys with them, so that he is able to decipher their communication in a way they don't realize. FMI refer to [this link](https://medium.com/@14wnrkim/diffie-hellman-key-exchange-724871ce78d9)

Here, we have a virtual machine that simulates a client that connects to a server and establishes an encoded communication using Diffie-Hellman protocol to convey a flag. Our job is at first poisoning their ARP cache and then key exchanging to foolish them so that we are able to intercept their intended communication.

P.S: If you needed the virtual machine, don't hesitate to contact me!
