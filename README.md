NOTE: This project is incomplete and not particularly useful. It is not yet 
intended for public consumption.

The only reason it isn't marked private is because I don't feel a need to pay
for an account just to keep eyes off!

# Tmod

Over the years I've coded up a number of useful utilities and implementations of
half-baked ideas. This project is an evolving intersection of a few.

Some of the code was originally written in straight C, and other in C++. This 
codebase is a mashup of the two. Best practices and aesthetics played no part 
here.

# Modeler

The most interesting chunk of code is based on some work I did with AI back around
2003. The goal is to use machine-learning to find interesting behavior in network 
traffic.

# Eventing

The second most interesting module provides a generic means to execute arbitrary 
code when a pattern is observed in network traffic. An example application would
be to have it execute a script when a part of a packet's payload matches a regular
expression. The script is passed useful information about the packet in the form 
of environment variables. The example script then sends an email to an admin with
a descritpion of the traffic and then updates iptables to block additional 
traffic from the client IP.
