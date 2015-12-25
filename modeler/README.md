
Interface to the ML backend
===========================

'Modeler' builds models of network traffic. It will serve as an interface to a
suite of machine-learning algorithms (hence it is likely to be renamed).

All the latest and greatest machine-learning libraries that I intend to 
experiment with have existing Python implementations. Consequently, for now the
modeler will serve as a preprocessor for extracting useful tidbits and getting 
them into a state wherin they can be consumed by a suite of machine-learning
implementations that I'm developing separately.

Hopefully after a few go-arounds I'll narrow down a preferred suite of ML 
techniques and will switch to C++ implementations.

===========================

Supervised methods will be trained with server responses to try to predict the
norm. If properly trained, failed predictions may indicate anomalous or 
suspicious behavior.

Unsupervised methods can identify "normal" patterns of network behavior, both 
from traffic flows, as well as traffic content.

Anomalous behavior will be logged and a user or admin will be notified. Said
user can then approve or disapprove of the traffic. Approved traffic will then
be added to the training set.

Several machine-learning algorithms do not support online, or streaming, 
training. They can only be updated periodically, such as during times of low
network load. Thus methods that do support online learning are the focus.

