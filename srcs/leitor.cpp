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
#include <netinet/ether.h> //header ethernet
#include <netinet/in_systm.h> //tipos de dados


#define BUFFER_SIZE 8192

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

int main(int argc, char *argv[])
{

    if (argc != 3)
    {
        std::cout << "Use: sudo ./nome-do-arquivo <ip-da-rede/mascara> <timeout_ms>" << std::endl;
        return 1;
    }

    int sockfd;
    int sockrv;
    int hosts_ativos = 0;

    std::string ipHost = argv[1];
    int timeout = atoi(argv[2]);
    std::string delimiter = "/";

    std::string baseIp = ipHost.substr(0, ipHost.find(delimiter));
    baseIp = baseIp.substr(0, baseIp.find_last_of(".") + 1) + "0";
    std::cout << "Base IP: " << baseIp << std::endl;
    std::string mask = ipHost.substr(ipHost.find(delimiter) + 1, ipHost.size());
    int numHosts = (1 << (32 - atoi(mask.c_str()))) - 2;
    std::cout << "Numero de hosts: " << numHosts << std::endl;

    // socket();

    sockfd = (socket(AF_INET, SOCK_RAW, IPPROTO_RAW));
    if (sockfd < 0)
    {
        errorFunction("Error to create the socket");
    }

    sockrv = (socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
    if (sockrv < 0)
    {
        errorFunction("Error to create the socket");
    }

    struct timeval timeoutReply;
    timeoutReply.tv_sec = timeout / 1000;
    timeoutReply.tv_usec = (timeout % 1000) * 1000;
    std::cout << "Timeout em milisegundos: " << timeoutReply.tv_usec * 1000 << std::endl;

    if (setsockopt(sockrv, SOL_SOCKET, SO_RCVTIMEO, &timeoutReply, sizeof(timeoutReply)) < 0)
    {
        errorFunction("Erro em bind do socket");
        exit(1);
    }

    // send ICMP

    struct sockaddr_in sendAddr;
    memset(&sendAddr, 0, sizeof(sendAddr));
    sendAddr.sin_family = AF_INET;
    sendAddr.sin_addr.s_addr = inet_addr(baseIp.c_str());
    char sendBuffer[BUFFER_SIZE];
    memset(sendBuffer, 0, BUFFER_SIZE);

    struct sockaddr_in receiveAddr;
    socklen_t addrLen = sizeof(receiveAddr);
    memset(&receiveAddr, 0, sizeof(receiveAddr));
    receiveAddr.sin_family = AF_INET;
    receiveAddr.sin_addr.s_addr = INADDR_ANY;
    char receiveBuffer[BUFFER_SIZE];
    memset(receiveBuffer, 0, BUFFER_SIZE);

    std::ofstream arquivo("hosts.txt");
    if (!arquivo)
    {
        std::cerr << "Error opening file for writing: " << "hosts.txt" << std::endl;
        return -1;
    }

    for (int i = 0; i < numHosts; i++)
    {
        sendAddr.sin_addr.s_addr = inet_addr(baseIp.c_str()) + htonl(i + 1);
        int packetSize = sizeof(struct iphdr) + sizeof(struct icmphdr);

        struct iphdr *ipHeader = (struct iphdr *)sendBuffer;
        ipHeader->version = 4;
        ipHeader->ihl = 5;
        ipHeader->tos = 0;
        ipHeader->tot_len = packetSize;
        ipHeader->id = htons(0);
        ipHeader->frag_off = 0;
        ipHeader->ttl = 255;
        ipHeader->protocol = IPPROTO_ICMP;
        ipHeader->saddr = inet_addr("192.198.1.1");
        ipHeader->daddr = sendAddr.sin_addr.s_addr;
        ipHeader->check = 0;
        ipHeader->check = checksum((unsigned short *)sendBuffer, sizeof(struct iphdr));

        struct icmphdr *icmp = (struct icmphdr *)(sendBuffer + sizeof(struct iphdr));
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(1);
        icmp->un.echo.sequence = htons(i);
        icmp->checksum = 0;
        icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr));

        std::cout << "Sending ICMP packet to: " << inet_ntoa(sendAddr.sin_addr) << std::endl;

        int sendLen = sendto(sockfd, sendBuffer, packetSize, 0, (struct sockaddr *)&sendAddr, (socklen_t)sizeof(sendAddr));
        if (sendLen < 0)
        {
            std::cerr << "Erro ao enviar mensagem ICMP" << std::endl;
        }      

        sleep(timeout / 1000);
        int recvLen = recvfrom(sockrv, receiveBuffer, sizeof(receiveBuffer), 0, (struct sockaddr *)&receiveAddr, &addrLen);
        if (recvLen < 0)
        {
            std::cout << "Host: " << inet_ntoa(sendAddr.sin_addr) << " inativo por tempo" << std::endl;
        }
        else
        {
             struct icmphdr *icmp_aux = (struct icmphdr *)receiveBuffer;   
            if (icmp_aux->type == ICMP_ECHOREPLY && ntohs(icmp_aux->un.echo.id) == 1 && ntohs(icmp_aux->un.echo.sequence) == i)
            {
                std::cout << "ICMP Reply received" << std::endl;
                hostList.push_back(std::make_pair(inet_ntoa(receiveAddr.sin_addr), icmp_aux->un.echo.sequence));
                arquivo << inet_ntoa(receiveAddr.sin_addr) << std::endl;
                std::cout << "Host: " << inet_ntoa(receiveAddr.sin_addr) << " ativo." << std::endl;
                hosts_ativos++;
            }
            else
            {
                std::cout << "Host: " << inet_ntoa(receiveAddr.sin_addr) << " inativo." << std::endl;
            }
        }
        //std::cout << "Host anterior: " << inet_ntoa(receiveAddr.sin_addr) << std::endl;
    }

    return 0;
}
