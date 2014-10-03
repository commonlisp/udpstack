#ifndef DEFINES_H 
#define DEFINES_H 1

// A number of useful structures for the program

struct ethHeader {
  unsigned char destaddr[6];
  unsigned char srcaddr[6];
  unsigned short type;
};

struct ipaddr {
  unsigned char addr[4];
};

struct ipsendrequest {
  unsigned char* destip;
  void* data;
  int len;
  struct ipsendrequest* next;
};

struct arphdr arptable[MAXIPS]; // Number of hosts on C class arptable
int currentEntry; // Number of entries in current ARP table

struct ipsendrequest* request;

#endif // STRUCTS_H
