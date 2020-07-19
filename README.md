# Chat app

Author: Stanislav Grebennik \
Email: stanislav.grebennik@gmail.com

### Introduction

This application was written as a part of TalTech Network Protocol Design (ITC8061) course.
More information about the course can be found here:
https://courses.cs.ttu.ee/pages/ITC8060

The app demonstrates the implementation of a protocol design, which was developed
during the course. The protocol description can be found in 'spec' file.

The application uses libnacl library to encrypt and decrypt the messages transfered 
between nodes. The encrypted payload then is encoded with base64, as agreed during 
the protocol designing phase. All UDP packets sent over the network are encoded 
using ascii standard.

### Installation guide
~~~
0. Start from the project root directory:
cd ~/app

1. Make sure you have python3 installed and pip version is up to date:
python3 -m pip install --upgrade pip

2. Install virtualenv module, if you don't yet have one:
pip3 install virtualenv

3. Create new venv:
python3 -m venv ./venv

4. Activate venv:
source venv/bin/activate

5. Install requirements:
pip3 install -r requirements.txt

6. Configure the application:
vi app.ini

7. Launch the chat app from project root directry:
python3 chat
~~~

### Using guide
##### Menu
To call a menu option, start with the '!' sign.
Possible menu options are:
~~~
!help - show help menu.
!online - show all online nodes.
!offline - show all offline nodes.
!all - show all known nodes.
!exit - exit the application.
~~~
The inserted string after the '!' sign must contain the option in any form, 
it does not have to equal to the menu name. For example:
~~~
!who is online right now?
~~~ 
... will return a list of all known online nodes.

##### Sending a text message
Sending a message is done by defining destination username right after '**>**'.\
Example: send a '**text message**' to the '**username**' node:
~~~
>username text message
~~~ 

##### Sending a file
Sending a file is done by defining destination username right after '**>>**'.\
Example: send '**path/to/a/file.txt**' file to the '**username**' node:
~~~ 
>>username path/to/a/file.txt
~~~ 

### Cool features
1. The application can work and exchange messages with other nodes even without any of
our UDP ports or IP addresses defined in the configuration file. It is possible to 
configure all of the other known nodes without even specifying their IP addresses, too! 
It should be noted that in order to establish communication with somebody, you have to 
configure networking address of at least one participant.

2. All nodes can change their statuses and be rediscovered automatically, no application
restart is needed.

3. Heartbeat class allows for a very flexible periodic updates and checks.

4. This protocol implementation is specifically made to be more visual and simple to 
grasp. There are multiple places of conversions from packet structure to python lists, 
messages cache is represented by python dictionary object, as well as other techniques 
used to make the code relatively simple to read. Some places definitely need an improvement, 
though. It should be mentioned that named techniques are not suitable for production and 
were made specifically for illustrative purposes.

### Problems and things to improve
1. Right now the implementation can send only textual files, sending a binary files
must be implemented in a future releases.

2. Large files must be cached on the disk during downloading. Right now the entire file
is stored in memory and is written to disk only when the receiver accepts it.

3. Logging to a log file should be improved further.

4. Improve menu, add additional features (like drawing the entire route tree etc)

5. Wrong application configuration can cause instability of connections to neighbours,
so i think configuration must be checked on startup.

6. Messenger class is way too big. It will make more sense to split it to smaller classes.
