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
#include <iostream>
#include "ipk-lookup.h"

int main(int argc, char **argv) {
    int index, c, timeout_seconds = 5;
    uint16_t type = TYPE_A, type_save;
    bool iterative = false;
    bool answerFound = false;
    bool iterNextAnswer = false;
    int iter = 0, iterNeeded = -1;

    opterr = 0;

    std::string server;
    std::string name;
    std::string iterLast;
    std::string stringEndChar;

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

    struct timeval timeout{};
    timeout.tv_sec = timeout_seconds;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    while (true) {
        unsigned char buf[65536];
        struct DNS_HEADER *dns_header;

        dns_header = (struct DNS_HEADER *) &buf;
        dns_header->ID = (unsigned short) getpid();
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
        if (iterative) {
            dns_header->RecursionDesired = 0;
        } else {
            dns_header->RecursionDesired = 1;
        }

        std::string dns_name;
        if (type == TYPE_PTR) {
            char tempbuf[100];

            if (inet_pton(AF_INET, name.c_str(), tempbuf)) {
                name = ipv4_to_pvtr4(name);
            } else if (inet_pton(AF_INET6, name.c_str(), tempbuf)) {
                name = ipv6_to_pvtr6(name);
            } else {
                fprintf(stderr, "ERROR: name must be valid IPv6 or IPv4!\n");
                exit(2);
            }
        }

        if (!iterative) {
            dns_name = name_to_dns_format(name);
        } else {
            if (iterNeeded == -1) {
                type_save = type;

                iterNeeded = 0;
                for (char c : name) {
                    if (c == '.') {
                        iterNeeded++;
                    }
                }
            }

            if (!iterNextAnswer) {
                if (iter % 2 == 0) {
                    type = TYPE_NS;
                    dns_name = name_to_dns_format(get_next_ns(name, iter));
                } else {
                    type = TYPE_A;

                    dns_name = name_to_dns_format(iterLast);
                }
            } else {
                dns_name = name_to_dns_format(name);
                type = type_save;
            }
        }

        unsigned long len = dns_name.length();
        if (len == 0) {
            len = 1;
        }

        memcpy(&buf[sizeof(struct DNS_HEADER)], dns_name.c_str(), len);
        memcpy(&buf[sizeof(struct DNS_HEADER) + len], stringEndChar.c_str(), 1);

        struct DNS_QUESTION *dns_question;
        dns_question = (struct DNS_QUESTION *) &buf[sizeof(struct DNS_HEADER) + (dns_name.length() + 1)];
        dns_question->QuestionClass = htons(1);
        dns_question->QuestionType = htons(type);

        socklen_t serverlen = sizeof(server_address);
        size_t header_and_question_size;
        size_t header_size;
        ssize_t bytestx;

        header_and_question_size = sizeof(struct DNS_HEADER) + (dns_name.length() + 1) + sizeof(struct DNS_QUESTION);
        header_size = sizeof(struct DNS_HEADER);

        bytestx = sendto(client_socket, buf, header_and_question_size, 0, (struct sockaddr *) &server_address,
                         serverlen);
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
        unsigned char *data = &buf[header_and_question_size];
        unsigned char *links_start = &buf[header_size - 12];

        int answers_count = ntohs(dns_header->AnswerCount);

        if (iterative) {
            int additionals_count = ntohs(dns_header->AdditionalCount);
            int nameservers_count = ntohs(dns_header->NameServerCount);
            answers_count += nameservers_count;
            answers_count += additionals_count;
        }

        struct DNS_RECORD answers[answers_count];

        parse_data(answers, answers_count, data, links_start);

        int answer_type;
        int start = 0;
        int answers_limit = answers_count;

        if (iterative) {
            answers_limit = 1;
        }

        for (int i = start; i < answers_limit; i++) {
            answer_type = ntohs(answers[i].Data->DataType);
            if ((answer_type == type) && (!iterative)) {
                answerFound = true;
            } else if ((answer_type == type) && iterative && iterNextAnswer) {
                answerFound = true;
            }

            int nameLen = 0;
            switch (answer_type) {
                case 1: {
                    char ipv4[INET_ADDRSTRLEN];
                    struct in_addr ipv4_addr{};
                    memcpy(&ipv4_addr, answers[i].Rdata, ntohs(answers[i].Data->DataLength));
                    inet_ntop(AF_INET, &ipv4_addr, ipv4, INET_ADDRSTRLEN);

                    if (!iterative || (type == TYPE_A)) {
                        printf("%s IN A %s\n", answers[i].DataName.c_str(), ipv4);
                    } else {
                        ++answers_limit;
                    }

                    inet_pton(AF_INET, ipv4, &(server_address.sin_addr));
                    break;
                }
                case 2: {
                    std::string ns = parse_name(answers[i].Rdata, links_start, &nameLen);
                    iterLast = ns;

                    if (!iterative || (type == TYPE_NS)) {
                        printf("%s IN NS %s\n", answers[i].DataName.c_str(), ns.c_str());
                    } else {
                        ++answers_limit;
                    }

                    break;
                }
                case 5: {
                    std::string cname = parse_name(answers[i].Rdata, links_start, &nameLen);
                    printf("%s IN CNAME %s\n", answers[i].DataName.c_str(), cname.c_str());
                    break;
                }
                case 12: {
                    std::string ptr = parse_name(answers[i].Rdata, links_start, &nameLen);
                    printf("%s IN PTR %s\n", answers[i].DataName.c_str(), ptr.c_str());
                    break;
                }
                case 28: {
                    char ipv6[INET6_ADDRSTRLEN];
                    struct in6_addr ipv6_addr{};
                    memcpy(&ipv6_addr, answers[i].Rdata, ntohs(answers[i].Data->DataLength));
                    inet_ntop(AF_INET6, &ipv6_addr, ipv6, INET6_ADDRSTRLEN);

                    printf("%s IN AAAA %s\n", answers[i].DataName.c_str(), ipv6);
                    break;
                }
                default:
                    break;
            }
        }

        iter += 1;

        if (!iterative) {
            break;
        } else {
            if (!answerFound) {
                if (iterNextAnswer) {
                    break;
                }

                if (type == TYPE_NS && answers_count == 0) {
                    break;
                }

                if (iter == iterNeeded * 2) {
                    iterNextAnswer = true;
                }
            } else {
                break;
            }
        }
    }

    if (!answerFound) {
        exit(1);
    }

    exit(0);
}

std::vector<std::string> explode(std::string const &s, char delim) {
    std::vector<std::string> result;
    std::istringstream iss(s);

    for (std::string token; std::getline(iss, token, delim);) {
        result.push_back(std::move(token));
    }

    return result;
}

std::string ipv4_to_pvtr4(std::string name) {
    std::string ptr_name = "in-addr.arpa";
    std::string reversed;

    auto exploded = explode(name, '.');
    std::reverse(exploded.begin(), exploded.end());

    for (auto piece : exploded) {
        reversed += piece + ".";
    }

    ptr_name = reversed + ptr_name;
    return ptr_name;
}

std::string ipv6_to_pvtr6(std::string name) {
    std::string ptr_name = "apra.6pi.";
    std::string reversed;

    auto exploded = explode(name, ':');
    int missing = static_cast<int>(8 - exploded.size());

    for (auto piece : exploded) {
        for (unsigned long i = piece.length(); i < 4; i++) {
            reversed += '0';
            reversed += '.';
        }

        if (piece.length() == 0) {
            while (missing > 0) {
                for (int i = 0; i < 4; i++) {
                    reversed += '0';
                    reversed += '.';
                }
                --missing;
            }
        }

        for (char i : piece) {
            reversed += i;
            reversed += '.';
        }
    }

    ptr_name += reversed;
    std::reverse(ptr_name.begin(), ptr_name.end());
    ptr_name.erase(0, 1);
    return ptr_name;
}

std::string name_from_dns_format(std::string dns_name) {
    std::string name;
    unsigned int position = 0;
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

std::string parse_name(unsigned char *data, unsigned char *links_start, int *nameLen) {
    bool link = false;
    bool linkDone = false;

    int linkValue = 0;
    int size = 0;
    *nameLen = 0;
    std::string name;

    while (*data != '\0') {

        if (link) {
            linkValue += *data;
            *nameLen = 2;
            linkDone = true;
        } else {
            name += *data;
        }

        if (*data >= 192) {
            link = true;
            linkValue += *data - 192;
            if (name.length() == 1) {
                name = "";
            } else {
                name = name.substr(0, name.size() - 1);
            }
        }

        ++size;
        data += 1;

        if (link && linkDone) {
            data = &links_start[linkValue];
            link = false;
            linkValue = 0;
            linkDone = false;
        }
    }

    if (name.empty()) {
        name = ".";
        *nameLen = 1;
    } else {
        name = name_from_dns_format(name);
    }

    return name;
}

void parse_data(struct DNS_RECORD *data_place, int count, unsigned char *data, unsigned char *links_start) {
    int nameLen = 0;

    for (int i = 0; i < count; i++) {
        data_place[i].DataName = parse_name(data, links_start, &nameLen);
        data += nameLen;

        data_place[i].Data = (struct DNS_RECORD_DATA *) (data);
        data += sizeof(struct DNS_RECORD_DATA);

        size_t answer_length = ntohs(data_place[i].Data->DataLength);
        data_place[i].Rdata = (unsigned char *) malloc(answer_length);

        for (unsigned int ii = 0; ii < answer_length; ii++) {
            data_place[i].Rdata[ii] = data[ii];
        }

        data += answer_length;
    }
}

std::string get_next_ns(std::string name, int iter) {
    auto exploded = explode(name, '.');
    std::reverse(exploded.begin(), exploded.end());

    if (iter == 0) {
        return "";
    } else {
        auto exploded = explode(name, '.');
        std::string part;

        int parts = iter / 2;
        for (int i = 0; i < parts; i++) {
            part += exploded[exploded.size() + i - parts];
            part += ".";
        }

        return part;
    }
}
