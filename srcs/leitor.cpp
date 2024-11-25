#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <thread>
#include <fcntl.h>
#include <fstream>
#include <vector>
#include <set>
#include <utility>
#include <functional>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define PORT 9000
#define BUFFER_SIZE 8192
#define MESSAGE_SERVER "Hello from client."

std::vector<std::pair<std::string, int>> hostList;

void errorFunction(const std::string &message)
{
    std::cerr << message << std::endl;
    exit(EXIT_FAILURE);
}

void receiveMessage(int sockfd)
{
    char buffer[BUFFER_SIZE];
    struct sockaddr_ll receiveAddr;
    socklen_t addrLen = sizeof(receiveAddr);

    while (true)
    {
        int recvLen = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&receiveAddr, &addrLen);
        if (recvLen < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            else
            {
                std::cerr << "Error to receive the message" << std::endl;
            }
        }
        else
        {
            //acessing the ethernet header
            struct ethhdr *eth = (struct ethhdr *)buffer;
            if (ntohs(eth->h_proto) == ETH_P_IP)
            {
                struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
                std::string protocol;

                // Check the protocol
                switch (ip->protocol)
                {
                    case IPPROTO_TCP:
                        protocol = "TCP";
                        break;
                    case IPPROTO_UDP:
                        protocol = "UDP";
                        break;
                    default:
                        protocol = "Unknown";
                        break;
                }

                std::cout << "Received packet from " << inet_ntoa(*(struct in_addr *)&ip->saddr) << " with protocol: " << protocol << std::endl;

                if (protocol == "TCP")
                {
                    struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
                    int sourcePort = ntohs(tcp->source);
                    int destPort = ntohs(tcp->dest);
                    if (sourcePort == 80 || destPort == 80)
                    {
                        std::cout << "HTTP packet detected" << std::endl;
                        
                        
                    }
                    else if (sourcePort == 443 || destPort == 443)
                    {
                        std::cout << "HTTPS packet detected" << std::endl;
                    }
                }
                else if (protocol == "UDP")
                {
                    struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
                    if (ntohs(udp->source) == 53 || ntohs(udp->dest) == 53)
                    {
                        std::cout << "DNS packet detected" << std::endl;
                    }
                }
            }
        }
    }
}



// Checksum function
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
    {
        sum += *buf++;
    }

    if (len == 1)
    {
        sum += *(unsigned char *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void sendICMPRequest(int sockfd, std::string ip, int numHosts)
{
    struct sockaddr_in hostsAddr;
    socklen_t addrLen = sizeof(hostsAddr);
    hostsAddr.sin_family = AF_INET;
    hostsAddr.sin_port = 0;
    hostsAddr.sin_addr.s_addr = inet_addr(ip.c_str());

    char buffer[64];
    memset(buffer, 0, sizeof(buffer));

    struct icmphdr *icmp = (struct icmphdr *)buffer;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(1);
    icmp->un.echo.sequence = htons(1);
    icmp->checksum = 0;
    icmp->checksum = checksum((unsigned short *)icmp, sizeof(buffer));

    for (int i = 0; i < numHosts; i++)
    {
        int sendLen = sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&hostsAddr, addrLen);
        if (sendLen < 0)
        {
            std::cerr << "Error sending ICMP message" << std::endl;
        }
    }
}

void receiveICMPReply(int sockfd)
{
    char buffer[BUFFER_SIZE];
    struct sockaddr_in hostsAddr;
    socklen_t addrLen = sizeof(hostsAddr);

    std::ofstream arquivo("hosts.txt");
    if (!arquivo) {
        std::cerr << "Error opening file for writing: " << "hosts.txt" << std::endl;
        return;
    }

    while (true)
    {
        int recvLen = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&hostsAddr, &addrLen);
        if (recvLen < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            else
            {
                std::cerr << "Error to receive the ICMP reply" << std::endl;
            }
        }
        else
        {
            struct icmphdr *icmp = (struct icmphdr *)buffer;
            if (icmp->type == ICMP_ECHOREPLY)
            {
                std::cout << "ICMP Reply received" << std::endl;
                hostList.push_back(std::make_pair(inet_ntoa(hostsAddr.sin_addr), icmp->un.echo.sequence));
                arquivo << inet_ntoa(hostsAddr.sin_addr) << std::endl;
            }
        }
    }
}

int main(int argc, char *argv[])
{

    if (argc != 3)
    {
        printf("Usage: %s <rede/máscara> <timeout_ms>\n", argv[0]);
        return 1;
    }

    int sockfd;
    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr)); // Inicializa a estrutura com zeros
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    char buffer[BUFFER_SIZE];
    std::string messageUser;

    std::string ipHost = argv[1];
    int timeout = atoi(argv[2]);
    std::string delimiter = "/";

    std::string ip = ipHost.substr(0, ipHost.find(delimiter));
    std::string mask = ipHost.substr(ipHost.find(delimiter) + 1, ipHost.size());
    int numHosts = (1 << (32 - atoi(mask.c_str()))) - 2;

    // socket();

    sockfd = (socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
    if (sockfd < 0){
        errorFunction("Error to create the socket");
    }

    int timeout_ms = timeout;
    struct timeval timeoutReply;
    timeoutReply.tv_sec = timeout_ms / 1000;
    timeoutReply.tv_usec = (timeout_ms % 1000) * 1000;

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &timeoutReply, sizeof(timeoutReply));

    // Bind the socket

    if (bind(sockfd, (struct sockaddr *)&localAddr, sizeof(localAddr)) < 0)
    {
        perror("Bind failed");
        close(sockfd);
        return 1;
    }

    // send ICMP

    sendICMPRequest(sockfd, ip, numHosts);

    // receive ICMP

    receiveICMPReply(sockfd);

    return 0;
}