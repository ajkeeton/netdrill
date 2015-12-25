Eventing
========

A library for generating events in response to certain network traffic.

A user provides a configuration file with a list of search patterns and 
corresponding actions. When a pattern is observed in the network flow, 
the action is performed.

For example, the following uses "exe..text" to a regular expression library 
(pcre). If the match succeeds, the following command is executed. In this 
case, it will for and exec the /bin/echo command:

    re;exe..test;exec /bin/echo pcre matched exec_test!

When a shell script serves as the action, useful data is passed via
environment variables. For example, the environment variable TMOD_HEX_PAYLOAD
contains a hexdump of the matching packet's payload. TMOD_SESSION describes the
IP and port combinations of the traffic flow.

Additional actions and pattern matching mechanisms are a TBD.
