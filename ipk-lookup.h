#ifndef IPK_LOOKUP_H
#define IPK_LOOKUP_H

uint16_t const TYPE_A = 1;
uint16_t const TYPE_NS = 2;
uint16_t const TYPE_CNAME = 5;
uint16_t const TYPE_PTR = 12;
uint16_t const TYPE_AAAA = 28;

//SOURCE: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682059(v=vs.85).aspx
struct DNS_HEADER {
    unsigned short ID;

    unsigned char RecursionDesired : 1;
    unsigned char Truncation : 1;
    unsigned char Authoritative : 1;
    unsigned char Opcode : 4;
    unsigned char IsResponse : 1;

    unsigned char ResponseCode :4;
    unsigned char CheckingDisabled :1;
    unsigned char AuthenticatedData :1;
    unsigned char Reserved :1;
    unsigned char RecursionAvailable :1;

    unsigned short QuestionCount;
    unsigned short AnswerCount;
    unsigned short NameServerCount;
    unsigned short AdditionalCount;
};

struct DNS_QUESTION {
    unsigned short QuestionType;
    unsigned short QuestionClass;
};

#pragma pack(push, 1)
struct DNS_RECORD_DATA {
    unsigned short DataType;
    unsigned short DataClass;
    unsigned int DataTTL;
    unsigned short DataLength;
};
#pragma pack(pop)

struct DNS_RECORD {
    unsigned char *DataName;
    struct DNS_RECORD_DATA *Data;
    unsigned char *Rdata;
};

#endif //IPK_LOOKUP_H
