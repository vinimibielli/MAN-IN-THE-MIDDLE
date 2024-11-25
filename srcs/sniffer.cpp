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
#include <iomanip>
#include <ctime>
#include <csignal>

#define BUFFER_SIZE 8192

void errorFunction(const std::string &message)
{
    std::cerr << message << std::endl;
    exit(EXIT_FAILURE);
}

std::vector<std::pair<std::pair<std::string, std::string>, std::string>> hostAcessed;

std::string extractHttpUrl(const char *httpData, int httpDataLen)
{
    std::string httpDataStr(httpData, httpDataLen);

    // Verificar se é uma solicitação GET
    if (httpDataStr.find("GET ") == 0)
    {
        // Extrair o caminho da solicitação
        size_t pathStart = httpDataStr.find(" ") + 1;
        size_t pathEnd = httpDataStr.find(" ", pathStart);
        std::string path = httpDataStr.substr(pathStart, pathEnd - pathStart);

        // Extrair o cabeçalho "Host"
        size_t hostStart = httpDataStr.find("Host: ") + 6;
        size_t hostEnd = httpDataStr.find("\r\n", hostStart);
        std::string host = httpDataStr.substr(hostStart, hostEnd - hostStart);

        // Combinar "Host" e caminho para formar o URL completo
        std::string urlAcessada = "http://" + host + path;
        std::cout << "HTTP URL accessed: " << urlAcessada << std::endl;
        return urlAcessada;
    }
    return "";
}

std::string extractDnsQuery(const char *dnsData, int dnsDataLen)
{
    // DNS header is 12 bytes
    if (dnsDataLen < 12)
        return "";

    const char *query = dnsData + 12;
    std::string domain;
    while (*query)
    {
        int len = *query++;
        if (len == 0)
            break;
        if (!domain.empty())
            domain += ".";
        domain.append(query, len);
        query += len;
    }
    return domain;
}

void snifferFunction(int sockfd, std::string ipVitima)
{
    char buffer[BUFFER_SIZE];

    // Bind the socket

    struct sockaddr_ll receiveAddr;
    memset(&receiveAddr, 0, sizeof(receiveAddr));
    receiveAddr.sll_family = AF_PACKET;
    receiveAddr.sll_protocol = htons(ETH_P_ALL);
    receiveAddr.sll_ifindex = if_nametoindex("eth0");
    socklen_t addrLen = sizeof(receiveAddr);

    if (bind(sockfd, (struct sockaddr *)&receiveAddr, sizeof(receiveAddr)) < 0)
    {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    std::cout << "Executando o sniffer" << std::endl;

    while (true)
    {
        // Recebe as mensagens
        int recvLen = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&receiveAddr, &addrLen);
        if (recvLen < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            else
            {
                std::cerr << "Erro para receber a mensagem" << std::endl;
            }
        }
        else
        {
            // Acessa a estrutura do cabeçalho Ethernet
            struct ethhdr *eth = (struct ethhdr *)buffer;

            // Verifica se o protocolo é IP
            if (ntohs(eth->h_proto) == ETH_P_IP)
            {

                // Obter a data e hora atual
                auto now = std::chrono::system_clock::now();
                std::time_t now_time = std::chrono::system_clock::to_time_t(now);
                std::tm *now_tm = std::localtime(&now_time);
                std::ostringstream oss;
                oss << std::put_time(now_tm, "%d/%m/%Y %H:%M:%S");
                std::string data_hora = oss.str();

                struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
                std::string protocol;

                // Verifica qual o protocolo
                switch (ip->protocol)
                {
                case IPPROTO_TCP: // caso seja TCP
                    protocol = "TCP";
                    break;
                case IPPROTO_UDP: // caso seja UDP
                    protocol = "UDP";
                    break;
                default: // caso seja outro protocolo
                    protocol = "Unknown";
                    break;
                }

                std::string ipReceive = inet_ntoa(*(struct in_addr *)&ip->saddr);

                // Verifica se o IP é o da vítima
                if (ipReceive != ipVitima)
                {
                    continue;
                }

                // Verifica se é HTTP, HTTPS ou DNS
                if (protocol == "TCP")
                {
                    struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
                    int sourcePort = ntohs(tcp->source);
                    int destPort = ntohs(tcp->dest);

                    // Caso a porta de origem ou destino seja 80, é HTTP
                    if (sourcePort == 80 || destPort == 80)
                    {
                        std::cout << "Pacote HTTP detectado" << std::endl;

                        // Obter o IP de origem e a URL acessada
                        std::string ipOrigem = inet_ntoa(*(struct in_addr *)&ip->saddr);

                        // HTTP Data
                        char *httpData = (char *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4 + tcp->doff * 4);
                        int httpDataLen = recvLen - (sizeof(struct ethhdr) + ip->ihl * 4 + tcp->doff * 4);

                        // Obter a URL acessada

                        std::string urlAcessada = extractHttpUrl(httpData, httpDataLen);

                        // Pushback no vetor
                        hostAcessed.push_back(std::make_pair(std::make_pair(ipOrigem, urlAcessada), data_hora));
                    }

                    // Caso a porta de origem ou destino seja 443, é HTTPS
                    else if (sourcePort == 443 || destPort == 443)
                    {
                        std::cout << "Pacote HTTPS detectado" << std::endl;
                    }
                }
                else if (protocol == "UDP")
                {
                    struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
                    if (ntohs(udp->source) == 53 || ntohs(udp->dest) == 53)
                    {
                        std::cout << "Pacote DNS detectado" << std::endl;

                        // Obter o IP de origem
                        std::string ipOrigem = inet_ntoa(*(struct in_addr *)&ip->saddr);

                        // Domínio acessado
                        char *dnsData = (char *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4 + sizeof(struct udphdr));
                        int dnsDataLen = recvLen - (sizeof(struct ethhdr) + ip->ihl * 4 + sizeof(struct udphdr));

                        // Obter o domínio acessado
                        std::string dnsDataStr = extractDnsQuery(dnsData, dnsDataLen);

                        // Pushback no vetor
                        hostAcessed.push_back(std::make_pair(std::make_pair(ipOrigem, dnsDataStr), data_hora));
                    }
                }
            }
        }
    }
}

void createHTML()
{
    std::cout << "Criando o arquivo HTML" << std::endl;
    std::ofstream htmlFile("index.html");
    if (!htmlFile)
    {
        std::cerr << "Erro ao abrir o arquivo para escrita: " << "index.html" << std::endl;
        return;
    }

    htmlFile << "<html>\n";
    htmlFile << "<header>\n";
    htmlFile << "<title>Historico de Navegacao</title>\n";
    htmlFile << "</header>\n";
    htmlFile << "<body>\n";
    htmlFile << "<ul>\n";

    for (const auto &host : hostAcessed)
    {
        htmlFile << "<li>" << host.second << " - " << host.first.first << " - <ahref" << host.first.second << "> " << host.first.second << "</a></li>\n";
    }

    htmlFile << "</ul>\n";
    htmlFile << "</body>\n";
    htmlFile << "</html>\n";
}

void signalHandler(int signum)
{
    // Chama a função para criar o arquivo HTML
    createHTML();

    // Termina o programa
    exit(signum);
}

int main()
{

    signal(SIGINT, signalHandler);

    int sockfd;
    std::string ipVitima = "";
    std::vector<std::string> ips;

    std::ifstream file("hosts.txt");

    if (!file.is_open())
    {
        std::cerr << "Error opening file: hosts.txt" << std::endl;
        return -1;
    }

    std::string line;
    while (std::getline(file, line))
    {
        ips.push_back(line);
    }

    file.close();

    for (int i = 0; i < ips.size(); i++)
    {
        std::cout << i << " - " << ips[i] << std::endl;
    }

    std::cout << "Digite o IP da vitima: ";

    std::cin >> ipVitima;


    // socket();

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("Socket creation failed");
        return 1;
    }
    // Sniffer

    //std::thread snifferFunctionThread(snifferFunction, sockfd, ipVitima);

    snifferFunction(sockfd, ipVitima);

    //createHTML();

    close(sockfd);

    return 0;
}