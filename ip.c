#ifndef IP_C
#define IP_C 1

// Implementation of IP routines

#include "defines.h"
#include "eth.c"

void ipsend(unsigned char destip[4], void* data, int len);

unsigned short cksum(unsigned short* buf, int count);

// Put a packet that I don't have a MAC address for into a linked list
// for later transmission
void ready(unsigned char destip[4], void* data, int len); 

// Sends out an IP packet given an IP address, some data, and the length
void ipsend(unsigned char destip[4], void* data, int len) {
  struct iphdr* myiphdr = malloc(sizeof(struct iphdr) + len);

  unsigned int dest;                            // destination in unsigned int
  unsigned char destMAC[6];
  unsigned char mysubnet[] = {192, 168, 100};   // hardwired subnet
  unsigned char ipbroadcast[4] = {192, 168, 100, 255};
  unsigned char macbroadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  unsigned char controllerIPar[4];              // holds the controller IP
  int foundmac = 0;                             // flag for polling whether
                                                // destination MAC was found
  int i = 0;                                    // Counter for loops

  // I'd like the destination address in both unsigned char[4] and 
  // unsigned int formats
  memcpy(&dest, destip, 4);
 
  // Only try to resolve the IP addr to a MAC addr if the destination is
  // in my subnet
  if (memcmp(destip, mysubnet, 3) == 0 && 
      memcmp(destip, ipbroadcast, 4) != 0) {
    // Try to find the MAC address of the destination in the ARP table
    
    for (i = 0; i < currentEntry; i++) {
      if (memcmp(arptable[i].ar_sip, &dest, 4) == 0) {
	memcpy(destMAC, arptable[i].ar_sha, 6);
	foundmac = 1;
      }
    }
   
    // If the MAC address is not in the ARP table, then request it
    if (foundmac == 0) {
      Arp_Request(destip);
      ready(destip, data, len);
      return;
    }
  } else if (memcmp(destip, ipbroadcast, 4) == 0) {
    memcpy(destMAC, macbroadcast, 6);
  } else {
    // Default to controller address as destination if the destination
    // is not in my subnet

    if (foundmac == 0) {
      for (i = 0; i < currentEntry; i++) {
	if (memcmp(arptable[i].ar_sip, &(machineInfo.controllerIP), 4) == 0) {
	  foundmac = 1;
	}
      }
      
      if (foundmac == 0) {
	Arp_Request(controllerIPar);

	ready(destip, data, len);
	return;
      }
    }
  }
  
  // At this point I should have my destination's MAC address

  // Now I'd like to construct the IP header

  myiphdr->version = 4;
  myiphdr->ihl = 5;

  myiphdr->tos = ntohs(IPTOS_PREC_ROUTINE);

  // The tot_len is the length of the header plus the length of the payload
  myiphdr->tot_len = ntohs(sizeof(struct iphdr) + len);

  // I really don't want to fragment
  myiphdr->id = 0;  
  myiphdr->frag_off = 0;

  // Use the default TTL
  myiphdr->ttl = IPDEFTTL;

  myiphdr->check = 0;
  myiphdr->protocol = IPPROTO_UDP; 
  
  memcpy(&(myiphdr->saddr), &(machineInfo.testIP), 4);
  memcpy(&(myiphdr->daddr), &dest, 4);

  // cksum expects count to be sizeof(struct iphdr) in number of 16-bit units
  // but sizeof returns in number of 8-bit units.
  myiphdr->check = cksum((unsigned short*) myiphdr, sizeof(struct iphdr) / 2);

  // Attach my payload
  memcpy(myiphdr + 1, (unsigned char*)data, len);

  specialsend(destMAC, myiphdr, sizeof(struct iphdr) + len, ntohs(ETH_P_IP) );
  free(myiphdr);
}

// Internet Checksum function
unsigned short cksum(unsigned short* buf, int count) 
{
  register unsigned long sum = 0;

  while (count--) {
    sum += *buf++;
    if (sum & 0xffff0000) {
      /* carry occurred.
	 so wrap around */
      sum &= 0xffff;
      sum++;
    }
  }

  return ~(sum & 0xffff);
}

void ready(unsigned char destip[4], void* data, int len) 
{
  struct ipsendrequest* newrequest = malloc(sizeof(struct ipsendrequest));
  
  newrequest->destip = malloc(4*sizeof(unsigned char));
  memcpy(newrequest->destip, destip, 4);
  
  newrequest->data = malloc(len);
  memcpy(newrequest->data, data, len);

  newrequest->len = len;

  newrequest->next = request;

  request = newrequest;
}

#endif // IP_C
