# TrafficBlame
A thing to run on your linux-based router so people can see who is hogging the internet connection.

# Demo time!
Right now it exposes a text-tastic web interface giving details of devices currently active.

    IP                  HOST                               IN            OUT          TOTAL        

    172.31.24.5         babbage                            1.5 kb/s      29.6 kb/s    31.1 kb/s    
    172.31.24.180       thynkpad.dhcp                      14.4 kb/s     2.6 kb/s     17.0 kb/s    
    172.31.24.86        crom-PC.dhcp                       5.5 kb/s      1.9 kb/s     7.5 kb/s     
    172.31.24.18        colin                              480.0 b/s     1.1 kb/s     1.6 kb/s     
    172.31.24.125       android-9930e046e0ac9e23.dhcp      118.0 b/s     118.0 b/s    236.0 b/s    
    172.31.24.159       Henry-Laptop.dhcp                  65.0 b/s      35.0 b/s     100.0 b/s    
    172.31.24.14        robocam2                           0.0 b/s       80.0 b/s     80.0 b/s 

# TODO
* Re-resolve the hostname if the mac associated with an IP changes
* Deuglify code
* Query param for data/s or raw output
* Nicer template output
* Json output
* Websockets?
