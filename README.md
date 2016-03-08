# eigrp
This is an implementation of CISCO's proprietary EIGRP routing protocol. The develpoment was based on the Informatinal RFC
published at https://tools.ietf.org/html/draft-savage-eigrp-02 . The protocol was developed to run at Debian distribution but
should be easy to port to other systems due to the lack of dependances (on purpose). The purpose of the project was to enable
network administrators to replace expensive routers with cheap computers that can do the same work. Currently it work only for IPv4.


#Files
/etc/eigrp/conf (same as the startup_config found in Cisco routers)        REQUIRED  
/etc/eigrp/settings               (extra options)                         OPTIONAL  
/etc/init.d/eigrp                 (service)                               OPTIONAL  
/usr/share/man/man8/eigrp.8.gz    (manpage)                               OPTIONAL  
/var/run.eigrp.pid                (pid)                                   REQUIRED  

#Installation
For debian users just download the package and install it as regular package 'dpkg -t eigrp_xxxxxxx'  
Note: IP packet forwarding is disabled by default at Debian wihch you will need to enable
  
Other users can download the source code and compile it. At the files section you can check which files are required for execution  

#Configuration
The basic configuration file (conf) described earlier has exactly the same format as the startp_config at Cisco routers. All rules and macros
apply with the only difference being the number of supported commands. You can check the samples to see all the supported commands.  
  
The settings file (settings) is an optional file to input setting that don't exist in a cisco router. The distinction between them
was done so i could maintain the exactly the similar format to the original startup_config
