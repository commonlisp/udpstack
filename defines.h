#ifndef MYDEFINES_H
#define MYDEFINES_H 1

// These are definitions that limit the 
// scope of the code and certain protocol
// constants such as UDP's protocol number

// The maximum number of IPs my ARP table keeps track of
#define MAXIPS 255 

// The maximum number of requests simultaneously in the queue
#define MAXREQS 10

// UDP's protocol number according to linux headers
#define IPPROTO_UDP 17

// BLAST connect port
#define CONNECTPORT 11199

#endif // MYDEFINES_H
