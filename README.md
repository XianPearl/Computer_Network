# Computer_Network
All programs related to computer networks which includes finding IP addresses to computing network hosts are all written in python language.


## CN Questions
1. **Various Transmission Media:** - **Guided Media:** - **Twisted Pair Cables:** Consists of pairs of wires twisted together to reduce electromagnetic 
interference. Commonly used in local area networks (LANs), especially with Ethernet cables (e.g., 
Cat5e, Cat6). - **Coaxial Cables:** Composed of a central conductor, insulating layer, metallic shield, and outer 
insulating layer. Used for cable TV and older Ethernet networks. - **Fiber Optic Cables:** Uses light to transmit data. Consists of a core, cladding, and protective 
outer layer. Offers high bandwidth, long-distance transmission, and resistance to electromagnetic 
interference. - **Unguided Media:** - **Radio Waves:** Used for wireless communication over long distances, such as Wi-Fi, cellular 
networks, and satellite communication. - **Microwaves:** Used for point-to-point communication links, satellite communication, and 
radar. - **Infrared:** Used for short-range communication in devices like remote controls and some 
wireless peripherals. 
2. **Utility of a Network Interface Card (NIC):** 
A NIC is a critical hardware component that enables a computer or other device to connect to a 
network. It converts data from the computer into a format suitable for transmission over the 
network and manages the physical layer of the network stack. NICs can be for wired connections 
(Ethernet) or wireless connections (Wi-Fi). They handle error checking and frame formatting, and 
each NIC has a unique MAC address that identifies the device on the network. 
3. **Difference Between Logical and Physical Address:** - **Logical Address:** An IP address assigned to each device on a network to facilitate routing and 
communication. It can change if the device connects to different networks (dynamic IP) or remain 
f
 ixed (static IP). Logical addresses are used by the network layer (Layer 3) of the OSI model. - **Physical Address:** A MAC address, a unique identifier assigned to the network interface card 
(NIC) of a device. It is used for data link layer (Layer 2) communications within the same network 
segment and is fixed to the hardware. 
4. **Comparison of Network Topologies:** - **Star Topology:** All devices are connected to a central hub or switch. If one device fails, it 
doesn’t affect others, but if the hub fails, the entire network goes down. It is easy to add or remove 
devices. - **Bus Topology:** All devices share a single communication line or backbone. If the backbone 
fails, the network goes down. It is cost-effective for small networks but not suitable for large or 
heavily loaded networks due to potential data collisions. - **Ring Topology:** Devices are connected in a circular manner. Each device has exactly two 
neighbors. Data travels in one direction, reducing collisions, but if one device or the connection fails, 
the entire network is affected unless there is a redundant path. - **Mesh Topology:** Each device is connected to every other device. This provides high 
redundancy and reliability. It is expensive and complex to install and maintain but offers excellent 
fault tolerance and load balancing. 
5. **Telnet:** 
Telnet is an application layer protocol used to provide a bidirectional interactive text-based 
communication facility over a network. It allows remote login and command execution on another 
machine as if the user were physically present at the machine. Telnet operates over TCP and is 
known for being insecure because it transmits data, including passwords, in plain text. 
6. **Firewalls:** 
Firewalls are network security devices or software that monitor and control incoming and outgoing 
network traffic based on predetermined security rules. They act as barriers between trusted internal 
networks and untrusted external networks (like the internet). Firewalls can be hardware-based, 
software-based, or a combination of both. They can perform various functions, including packet 
f
 iltering, stateful inspection, proxying, and logging. 
7. **Steps to Configure File Transfer Protocol (FTP):** - **Install FTP Server Software:** Choose and install FTP server software, such as FileZilla Server, 
vsftpd, or ProFTPD, on the host machine. - **Configure Server Settings:** Adjust server settings, including setting up the listening port 
(default is port 21), passive mode settings, and encryption options (e.g., FTPS for secure 
transmission). - **Set Up User Accounts and Permissions:** Create user accounts and configure permissions for 
access to specific directories. Ensure users have the necessary read/write access based on their roles. - **Configure Directories:** Define home directories for users and set appropriate permissions for 
accessing these directories. - **Start FTP Server:** Launch the FTP server service and ensure it is running correctly. - **Connect Using FTP Client:** Use an FTP client, such as FileZilla, WinSCP, or command-line FTP, 
to connect to the server using the configured user credentials. 
8. **DNS (Domain Name System):** 
DNS is a hierarchical and decentralized naming system for devices connected to the internet or a 
private network. It translates human-readable domain names (e.g., www.example.com) into 
numerical IP addresses (e.g., 192.0.2.1). DNS uses a distributed database maintained by a network of 
name servers. Key components include: - **DNS Resolver:** A client-side service that queries DNS servers to resolve domain names. - **DNS Server:** A server that stores DNS records and responds to queries from DNS resolvers. - **Root Servers:** The top level of the DNS hierarchy, directing queries to the appropriate top
level domain (TLD) servers. - **TLD Servers:** Servers that handle the top-level domains (e.g., .com, .org) and direct queries to 
authoritative DNS servers for specific domains. 
9. **Comparison of Hub, Switch, and Router:** - **Hub:** A simple network device that broadcasts incoming data packets to all devices 
connected to its ports. Hubs operate at the physical layer (Layer 1) and do not filter or manage traffic, 
leading to potential collisions in the network. 
- **Switch:** A more advanced device that operates at the data link layer (Layer 2). It receives data 
packets and forwards them only to the specific device (port) that the data is intended for, based on 
MAC addresses. Switches reduce collisions and improve network efficiency. - **Router:** A network device that operates at the network layer (Layer 3). It routes data packets 
between different networks, typically using IP addresses. Routers can connect and manage traffic 
between multiple networks, providing internet connectivity and supporting various protocols. 
10. **Types of Cable Used in Computer Networks:** - **Twisted Pair Cables:** - **Unshielded Twisted Pair (UTP):** Commonly used in Ethernet networks (e.g., Cat5e, Cat6) 
due to its low cost and ease of installation. - **Shielded Twisted Pair (STP):** Provides better protection against electromagnetic 
interference, used in environments with high interference. - **Coaxial Cables:** Consists of a central conductor, insulating layer, metallic shield, and outer 
insulating layer. Used for cable television, broadband internet, and older Ethernet networks. - **Fiber Optic Cables:** Uses light to transmit data, providing high bandwidth, long-distance 
transmission, and resistance to electromagnetic interference. Used in backbone networks, data 
centers, and for high-speed internet connections. 
11. **Client-Server Communication Paradigm:** 
In the client-server model, clients (end-user devices) request services or resources from a 
centralized server. The server processes these requests and provides the necessary responses. This 
model is widely used in networking, where the server hosts resources such as web pages, files, 
databases, or applications, and clients access these resources over a network. Key features include: - **Centralization:** Servers provide centralized management and control of resources. - **Scalability:** Servers can be scaled to handle multiple client requests simultaneously. - **Security:** Centralized servers can implement robust security measures to protect resources. 
12. **Unicast, Broadcast, & Multicast:** - **Unicast:** A communication method where data is sent from one sender to one specific 
receiver. It is the most common form of communication in networks, used for one-to-one 
interactions such as web browsing and file transfers. - **Broadcast:** A communication method where data is sent from one sender to all devices in a 
network segment. Broadcasts are used for network discovery protocols and certain types of 
messaging. However, excessive broadcasting can lead to network congestion. - **Multicast:** A communication method where data is sent from one sender to a specific group 
of devices that have expressed interest in receiving the data. Multicast is efficient for streaming 
media, video conferencing, and other applications where the same data needs to be delivered to 
multiple recipients simultaneously without duplicating the data for each receiver.
