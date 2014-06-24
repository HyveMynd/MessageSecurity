Message Security
================

University of Utah CS4480 Assignment 3 Spring 2014. 


Usage:
java -jar [-options] [jar-name] [IP address] [port]

[jar-name]:
	The name of the Message Security jar.

[-options]:
    The only option available is '-v'. This will turn logging on past only error messages and will show the inner
    workings of the system.

[IP address]:
    A valid Ip address to connect or listen to.

[port]:
    The target port number to connect or listen to.

NOTE: In this case the Bob module acts as the server and will listen for Alice to connect.

CADE USERS: CADE users must use jdk-1.7. It can be found in /usr/bin/java
            (the default jdk-1.6 is in /usr/local/bin/java)
