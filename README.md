This file explains the implementation of TelNet-TCP/IP using free rtos.
The process goes as mentioned below
1. Initiate the IP stack and after processing the link ensure that the network is up and IP credentials have been assigned(can be static or dynamic).
2. Open the socket and bind it with a port number.
3. Then put the socket created in listening mode.
4. Then it keeps checking for incoming connection and if present the connection gets established.
