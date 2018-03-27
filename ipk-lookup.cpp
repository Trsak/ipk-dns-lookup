#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <cstring>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include "ipk-lookup.h"

void print_query(unsigned char *query, int len) {
    int i;

    printf("in hex\n");
    for (i = 0; i < len; i++) {
        printf("%02hhX ", query[i]);

        if (i % 16 == 0 && i != 0) {
            printf("\n");
        }
    }
    printf("\nin ascii\n");

    for (i = 0; i < len; i++) {
        printf("%c ", query[i] < (unsigned char) 0x21 ? '.' : query[i]);

        if (i % 16 == 0 && i != 0) {
            printf("\n");
        }
    }
    printf("\n");
}

//SOURCE: https://stackoverflow.com/a/12967010
std::vector<std::string> explode(std::string const &s, char delim) {
    std::vector<std::string> result;
    std::istringstream iss(s);

    for (std::string token; std::getline(iss, token, delim);) {
        result.push_back(std::move(token));
    }

    return result;
}

std::string ipv6_to_pvtr6(std::string name) {
    std::string ptr_name = "apra.6pi.";
    std::string reversed;

    auto exploded = explode(name, ':');
    int missing = static_cast<int>(8 - exploded.size());

    for (auto piece : exploded) {
        for (int i = 1; i <= 4; i++) {
            if (piece.length() < i) {
                reversed += '0';
            } else {
                reversed += piece[i - 1];
            }
            reversed += ".";

            if (i == 4 && missing > 0 && piece.empty()) {
                i = 0;
                --missing;
            }
        }
    }

    ptr_name += reversed;
    std::reverse(ptr_name.begin(), ptr_name.end());
    ptr_name.erase(0, 1);
    return ptr_name;
}

std::string name_to_dns_format(std::string name) {
    std::string dns_name;

    auto exploded = explode(name, '.');

    for (auto piece : exploded) {
        int num = piece.length();
        dns_name += num;
        dns_name += piece;
    }

    return dns_name;
}

std::string name_from_dns_format(std::string dns_name) {
    std::string name;
    int position = 0;
    std::vector<int> dots;

    for (char c : dns_name) {
        if (isprint(c)) {
            name += c;
        } else {
            dots.push_back(c);
        }

        ++position;
    }

    position = 0;
    for (int pos : dots) {
        position += pos;
        name.insert(position, ".");
        ++position;
    }

    return name;
}

unsigned char *parse_name(unsigned char *reader, unsigned char *buffer, size_t dataSize, int *step) {
    int size = 0;
    int back = 10;
    bool link = false;
    std::string name;

    while (*reader != '\0') {
        if (link) {
            back += *reader;
        }

        if (*reader == 192) {
            link = true;
        }

        ++size;
        reader += 1;
    }

    reader = &buffer[dataSize - back];

    while (*reader != '\0') {
        name += *reader;
        reader += 1;
    }

    *step += size;

    name = name_from_dns_format(name);
    return (unsigned char *) name.c_str();
}

int main(int argc, char **argv) {
    int index, c, timeout_seconds = 5;
    uint16_t type = TYPE_A;
    bool iterative = false;
    unsigned char buf[65536];

    opterr = 0;

    std::string server;
    std::string name;

    while ((c = getopt(argc, argv, "ihs:T:t:")) != -1) {
        switch (c) {
            case 'h':
                if (argc != 2) {
                    fprintf(stderr, "ERROR: -h parameter can be only used standalone!\n");
                    exit(2);
                }
                //TODO: HELP message
                printf("---------- HELP ----------\n");
                exit(0);
            case 's':
                server = optarg;
                break;
            case 'T':
                char *ptr;
                timeout_seconds = static_cast<int>(strtol(optarg, &ptr, 10));
                if (strlen(ptr) != 0) {
                    fprintf(stderr, "ERROR: Timeout must be integer!\n");
                    exit(2);
                }
                break;
            case 't':
                if (strcmp(optarg, "A") == 0) {
                    type = TYPE_A;
                } else if (strcmp(optarg, "AAAA") == 0) {
                    type = TYPE_AAAA;
                } else if (strcmp(optarg, "NS") == 0) {
                    type = TYPE_NS;
                } else if (strcmp(optarg, "PTR") == 0) {
                    type = TYPE_PTR;
                } else if (strcmp(optarg, "CNAME") == 0) {
                    type = TYPE_CNAME;
                } else {
                    fprintf(stderr, "ERROR: Unknown type!\n");
                    exit(2);
                }
                break;
            case 'i':
                iterative = true;
                break;
            case '?':
                if (optopt == 's' || optopt == 't' || optopt == 'T') {
                    fprintf(stderr, "ERROR: Option %c requires an argument.\n", optopt);
                } else if (isprint(optopt)) {
                    fprintf(stderr, "ERROR: Unknown option `-%c'.\n", optopt);
                } else {
                    fprintf(stderr, "ERROR: Unknown option character `\\x%x'.\n", optopt);
                }

                exit(2);
            default:
                abort();
        }
    }

    for (index = optind; index < argc; index++) {
        if (!name.empty()) {
            fprintf(stderr, "ERROR: Unknown non-option argument: %s.\n", argv[index]);
            exit(2);
        }

        name = argv[index];
    }

    if (server.empty()) {
        fprintf(stderr, "ERROR: Missing server parameter!\n");
        exit(2);
    } else if (name.empty()) {
        fprintf(stderr, "ERROR: Missing name argument!\n");
        exit(2);
    }

    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(53);

    int server_address_check = inet_pton(AF_INET, server.c_str(), &(server_address.sin_addr));
    if (server_address_check <= 0) {
        fprintf(stderr, "ERROR: Server argument must be valid IPv4!\n");
        exit(2);
    }

    int client_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_socket <= 0) {
        fprintf(stderr, "ERROR: Error while creating socket!\n");
        exit(1);
    }

    struct DNS_HEADER *dns_header;

    dns_header = (struct DNS_HEADER *) &buf;
    dns_header->ID = (unsigned short) getpid();
    dns_header->RecursionDesired = 1;
    dns_header->Truncation = 0;
    dns_header->Authoritative = 0;
    dns_header->Opcode = 0;
    dns_header->IsResponse = 0;
    dns_header->ResponseCode = 0;
    dns_header->CheckingDisabled = 0;
    dns_header->AuthenticatedData = 0;
    dns_header->Reserved = 0;
    dns_header->RecursionAvailable = 0;
    dns_header->QuestionCount = htons(1);
    dns_header->AnswerCount = 0;
    dns_header->NameServerCount = 0;
    dns_header->AdditionalCount = 0;

    auto dns_name = name_to_dns_format(name);
    memcpy(&buf[sizeof(struct DNS_HEADER)], dns_name.c_str(), dns_name.length());

    struct DNS_QUESTION *qinfo;
    qinfo = (struct DNS_QUESTION *) &buf[sizeof(struct DNS_HEADER) + (dns_name.length() + 1)];
    qinfo->QuestionType = htons(type);
    qinfo->QuestionClass = htons(1);

    struct timeval timeout{};
    timeout.tv_sec = timeout_seconds;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    socklen_t serverlen = sizeof(server_address);
    size_t header_and_question_size;
    ssize_t bytestx;

    header_and_question_size = sizeof(struct DNS_HEADER) + (dns_name.length() + 1) + sizeof(struct DNS_QUESTION);

    bytestx = sendto(client_socket, buf, header_and_question_size, 0, (struct sockaddr *) &server_address, serverlen);
    if (bytestx < 0) {
        fprintf(stderr, "ERROR: Could not send packet!\n");
        exit(1);
    }

    bytestx = recvfrom(client_socket, buf, 65536, 0, (struct sockaddr *) &server_address, &serverlen);
    if (bytestx < 0) {
        if (errno == 11) {
            fprintf(stderr, "ERROR: Recv timed out!\n");
            exit(1);
        }

        fprintf(stderr, "ERROR: Could not recieve packet!\n");
        exit(1);
    }

    dns_header = (struct DNS_HEADER *) buf;
    unsigned char *reader = &buf[header_and_question_size];

    int andswers_count = ntohs(dns_header->AnswerCount);
    struct DNS_RECORD answers[andswers_count];

    return 0;
}