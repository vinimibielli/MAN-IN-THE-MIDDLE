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

#define PORT 9000
#define BUFFER_SIZE 8192
#define MESSAGE_SERVER "Hello from client."

std::vector<std::pair<std::string, int>> hostList;

void errorFunction(const std::string &message)
{
    std::cerr << message << std::endl;
    exit(EXIT_FAILURE);
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

    std::ofstream outFile("hosts.txt");
    if (!outFile) {
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
                outFile << "Host: " << inet_ntoa(hostsAddr.sin_addr) << ", RTT: " << icmp->un.echo.sequence << " ms" << std::endl;
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
    struct sockaddr_in hostsAddr;
    socklen_t addrLen = sizeof(hostsAddr);

    char buffer[BUFFER_SIZE];
    std::string messageUser;

    std::string ipHost = argv[1];
    int timeout = atoi(argv[2]);
    std::string delimiter = "/";

    std::string ip = ipHost.substr(0, ipHost.find(delimiter));
    std::string mask = ipHost.substr(ipHost.find(delimiter) + 1, ipHost.size());
    int numHosts = (1 << (32 - atoi(mask.c_str()))) - 2;

    // socket();

    sockfd = (socket(AF_INET, SOCK_RAW, IPPROTO_RAW));
    if (sockfd < 0)
        errorFunction("Error to create the socket");

    int timeout_ms = timeout;
    struct timeval timeoutReply;
    timeoutReply.tv_sec = timeout_ms / 1000;
    timeoutReply.tv_usec = (timeout_ms % 1000) * 1000;

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &timeoutReply, sizeof(timeoutReply));

    // Bind the socket

    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
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