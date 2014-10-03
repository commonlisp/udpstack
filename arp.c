#ifndef ARP_C
#define ARP_C 1

#include "defines.h"

void printarp(struct arphdr myarphdr);

void Arp_Request(unsigned char destIP[4]);

void Arp_Response(unsigned char dest[6], unsigned char destIP[4]);

void arp_recv(struct ethHeader* pMyHeader);

// Print out the source MAC/IP and destination MAC/IP from a 
// given ARP header structure
void printarp(struct arphdr myarphdr) 
{
  int i;

  netprintf("\nARP Source MAC: ");

  for (i = 0; i < 6; i++)
    netprintf("%x", myarphdr.ar_sha[i]);
  
  netprintf("\nARP Source IP: ");
  
  for (i = 0; i < 4; i++)
    netprintf("%d.", myarphdr.ar_sip[i]);
  
  netprintf("\nARP Destination MAC: ");
  
  for (i = 0; i < 6; i++)
    netprintf("%x", myarphdr.ar_tha[i]);
  
  netprintf("\nARP Destination IP: ");
  
  for (i = 0; i < 4; i++)
    netprintf("%d.", myarphdr.ar_tip[i]);
  
  netprintf("\n");
}

// Packages, initializes, and sends an ARP Request packet to the
// given address  
void Arp_Request(unsigned char destIP[4]) 
{
  struct ethHeader* myHdr = malloc(sizeof(struct ethHeader) + 
				   sizeof(struct arphdr));
  struct arphdr myarphdr;
  
  unsigned char dest[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  
  unsigned char dummyMAC[6] = { };

  myarphdr.ar_hrd = ntohs(ARPHRD_ETHER);
  myarphdr.ar_pro = ntohs(ETH_P_IP);
  myarphdr.ar_op = ntohs(ARPOP_REQUEST);
  myarphdr.ar_hln = 6;
  myarphdr.ar_pln = 4;

  // My addresses are the new source addresses
  memcpy(myarphdr.ar_sha, &(machineInfo.testMAC), ETH_ALEN);
  memcpy(myarphdr.ar_sip, &(machineInfo.testIP.s_addr), 4);

  // Use my hardware address as the space filler for the target MAC?
  memcpy(myarphdr.ar_tha, dummyMAC, ETH_ALEN);
  memcpy(myarphdr.ar_tip, destIP, 4);

  // Set destination and source addresses
  memcpy(myHdr->destaddr, dest, 6);
  memcpy(myHdr->srcaddr, &(machineInfo.testMAC), 6);

  // Set protocol type
  myHdr->type = ntohs(ETH_P_ARP);

  memcpy(myHdr + 1, &(myarphdr), sizeof(struct arphdr));

  netsend(myHdr, sizeof(struct ethHeader) + sizeof(struct arphdr));
}

// Creates, initializes, and sends an ARP Reply packet with the given 
// destination addresses
void Arp_Response(unsigned char dest[6], unsigned char destIP[4]) 
{
  struct ethHeader* myHdr = malloc(sizeof(struct ethHeader) + 
				   sizeof(struct arphdr));
  struct arphdr myarphdr;

  myarphdr.ar_hrd = ntohs(ARPHRD_ETHER);
  myarphdr.ar_pro = ntohs(ETH_P_IP);
  myarphdr.ar_op = ntohs(ARPOP_REPLY);
  myarphdr.ar_hln = 6;
  myarphdr.ar_pln = 4;

  // My addresses are the new source addresses
  memcpy(myarphdr.ar_sha, &(machineInfo.testMAC), ETH_ALEN);
  memcpy(myarphdr.ar_sip, &(machineInfo.testIP.s_addr), 4);

  memcpy(myarphdr.ar_tha, dest, ETH_ALEN);
  memcpy(myarphdr.ar_tip, destIP, 4);

  // Set destination and source addresses
  memcpy(myHdr->destaddr, dest, 6);
  memcpy(myHdr->srcaddr, &(machineInfo.testMAC), 6);

  // Set protocol type
  myHdr->type = ntohs(ETH_P_ARP);

  memcpy(myHdr + 1, &(myarphdr), sizeof(struct arphdr));

  netsend(myHdr, sizeof(struct ethHeader) + sizeof(struct arphdr));
}

// Handles ARP Requests and Response by responding with ARP and putting
// the relevant data in my ARP table
void arp_recv(struct ethHeader* pMyHeader) 
{
    struct arphdr* pMyARPhdr;

   // Fit an ARP message to the proper struct
    
    pMyARPhdr = (struct arphdr*)(pMyHeader + 1);
    
    if (htons(pMyARPhdr->ar_op) == ARPOP_REQUEST) {
      // When an ARP Request is spotted

      
      if (memcmp(pMyARPhdr->ar_tip,
	  &(machineInfo.testIP.s_addr), 4) == 0) {
	Arp_Response(pMyARPhdr->ar_sha, pMyARPhdr->ar_sip); // Reply
      }

      // If the ARP table is full, overwrite the oldest entry
      if (currentEntry > MAXIPS)
		currentEntry = 0;

      arptable[currentEntry++] = *pMyARPhdr;
    } else if (htons(pMyARPhdr->ar_op) == ARPOP_REPLY) {
      // When an ARP Reply is spotted, print out the contents
      // and record it in the ARP table.

      // If the ARP table is full, overwrite the oldest entry
      if (currentEntry >= MAXIPS)
		currentEntry = 0;

      arptable[currentEntry++] = *pMyARPhdr;
    }
}

#endif // ARP_C
