#include <netprintf.h> // netprintf
#include <stdio.h> // printf
#include <netsend.h> // netsend routine
#include <machineInfo.h> // machineInfo struct
#include <string.h> // strncpy
#include <stdlib.h> // malloc
#include "if_ether.h" // ETH_P_ARP and ETH_P_IP constants
#include "if_arp.h" // ARP frame structs
#include "ip.h" // IP Header struct iphdr
#include "udp.h" // UDP Header struct udphdr
#include "defines.h" // Constant Definitions
#include "structs.h" // Utility structures
#include "arp.c" // My printarp, ARP_Request, and ARP_Response routines
#include "eth.c" // My Ethernet specialsend routine
#include "ip.c" // My ipsend and cksum routines
#include "myudp.c" // My udpsend routine
#include "spp.c" // My sppbroadcast, sppsend, and reportToTink routines
#include "blast.c"

// More include files probably needed here.

/*
 * net.c
 * This file contains the most basic functionality for interface with
 * the administrative backend of the net class kernel.  It is intended to 
 * be given to the students at the beginning of the project.
 */

/*
 * This is your status function.
 * It is called whenever a status message is requested from the console.
 * Functionality: When udp message on port 2440-2449 is sent to 192.168.200.x,
 * this function is called with argument port-2440.
 *
 * netprintf works just like printf, but to the remote console and not to the
 * (nonexistent) monitor.
 */
void status (int num)
{
  int count;
  int len;

  // Tinkerbell MAC address
  unsigned char dest[6] = {0x00, 0xd0, 0xb7, 0x82, 0x4e, 0xbd};

  unsigned char destip[] = {192, 168, 100, 200};

  unsigned char myudphdr[] = {0x04, 0x57, 0x08, 0xae, 0x00, 0x18, 0x00,
			      0x00, 'g', 'k' , 'u', 'a', 'n', 
			      '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
			      '\0', '\0', '\0'};

  // Sample UDP payload
  unsigned char data[] = { 
    0x45, 0x00, 0x00, 0x2e, 0x09, 0xb1, 0x00, 0x00, 0x30, 0x11, 0x36, 0x2e, 
    0xc0, 0xa8, 0x64, 0xc7, 0xc0, 0xa8, 0x64, 0xc8, 0x30, 0x39, 0x27, 0x0f, 
    0x00, 0x1a, 0x00, 0x00, 'g', 'k', 'u', 'a', 'n', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'};

  unsigned char destIP[4] = { 192, 168, 100, 200 }; // Tink

  len = sizeof(data);

  netprintf("This is status %d\n", num);

  netprintf("\n");

  if (num == 1) {
    specialsend(dest, data, len, ntohs(ETH_P_IP));
  } else if (num == 2) {
    Arp_Request(destIP);
  } else if (num == 3) {
    netprintf("ARP Table:\n");

    for (count = 0; count < currentEntry; count++) {
      netprintf("======Entry %d========", count);
      printarp(arptable[count]);
    }
  } else if (num == 4) {
    netprintf("Try to send an IP packet.\n");
    ipsend(destip, myudphdr, 24);
  } else if (num == 5) {
    netprintf("Try to send an UDP packet.\n");
    udpsend(destip, "gkuan", 5, 2222, 2222);
  } else if (num == 6) {
    netprintf("Try to broadcast SPP query.\n");
    sppbroadcast();
  } else if (num == 7) {
    blastConnect(destIP);
  }
}

// netrecv: This function processes any incoming frames
void netrecv(void* frame, int len) {

  unsigned char broadcastAddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  unsigned char ipbroadcastAddr[4] = {255, 255, 255, 255};
  unsigned char netmask[4] = {255, 255, 255, 0};
  unsigned int unetmask;
  unsigned char destip[4];
  
  int i = 0; // My generic loop counter

  struct ethHeader* pMyHeader = (struct ethHeader*)frame;

  struct iphdr* pMyIPhdr;
  struct ipaddr* pMyIPaddr;
  struct udphdr* pMyUDPhdr;

  char* currentpos;

  memcpy(&unetmask, netmask, 4); // Initialize my netmask

  // Determine message protocol type
  if (pMyHeader->type == htons(ETH_P_ARP)) {
    arp_recv(pMyHeader);
  }
  
  if (pMyHeader->type == htons(ETH_P_IP)) {
    
    // Get a handle on the IP header
    pMyIPhdr = (struct iphdr*)(pMyHeader + 1);

    // Is this IP packet an UDP packet?
    if (pMyIPhdr->protocol == IPPROTO_UDP) {
      pMyUDPhdr = (struct udphdr*)(pMyIPhdr + 1);

      // Detect and cater to ECHO packets
      if ((htons(pMyUDPhdr->dest) == 7) &&
	  (memcmp(&(pMyIPhdr->daddr), &(machineInfo.testIP.s_addr) ,4) == 0)) 
      {
	currentpos = (char*)(pMyUDPhdr + 1);
	netprintf("ECHO (length : %d): ", 
		  htons(pMyUDPhdr->len) - sizeof(struct udphdr));
	
	for (i = 0; i < (htons(pMyUDPhdr->len)- sizeof(struct udphdr)); i++) {
	  netprintf("%c ", *(currentpos++));
	}

	memcpy(destip, &(pMyIPhdr->saddr), 4);
	udpsend(destip, 
		pMyUDPhdr + 1, 
		htons(pMyUDPhdr->len) - sizeof(struct udphdr),
		7, 
		7);

      } else if (htons(pMyUDPhdr->dest) == 2002) {
	spp_recv(pMyUDPhdr);
      } else if (htons(pMyUDPhdr->dest) == CONNECTPORT) {
	blastRecv(pMyUDPhdr);
      }
    }
      
    // Check if the IP Packet is for me
    if ( memcmp(&(pMyIPhdr->daddr), 
		&(machineInfo.testIP.s_addr), 4) == 0 ) {

      // Print out the IP address of the source host
      pMyIPaddr = (struct ipaddr*)&(pMyIPhdr->saddr);
      
      
    } else if ((memcmp(&(pMyIPhdr->daddr), &(ipbroadcastAddr), 4) == 0) ||
	       pMyIPhdr->daddr | unetmask) {

      pMyIPaddr = (struct ipaddr*)&(pMyIPhdr->saddr);

    }		          
  }
}

/*
 * Perform tasks on startup.
 */
void netstartup()
{
  request = NULL;
}

/*
 * Perform actions periodically on a timer. (Once per second)
 */
void nettimer()
{
  struct ipsendrequest* currentrequest = request;
  unsigned char destip[] = {192, 168, 100, 200};

  if (request != NULL) {
    request = request->next;
    ipsend(currentrequest->destip, currentrequest->data, currentrequest->len);
    free(currentrequest->destip);
    free(currentrequest->data);
    free(currentrequest);
  }

  if (Retry_Timer > 0) {
    Retry_Timer--;
  } else if (Retry_Timer == 0) {
    netprintf("Retry_Timer expired.\n");
    
    NumRetries++;

    if (NumRetries == 1 || NumRetries == 2) {
      blastSRR(destip, totalfragmask);
      Last_Frag = -1;
      Retry_Timer = MAXRETRYTIME;
    } else if (NumRetries == 3) {
      netprintf("Giving up BLAST session.\n");
      NumRetries = 0;
      Last_Frag = -1;
      Retry_Timer = -1;
    }
  }

  // Increment Last_Frag for BLAST
  if (Last_Frag > 0) {
    Last_Frag_Decr();
  } else if (Last_Frag == 0) {
    netprintf("LAST_FRAG timer expired. blastSource %d\n", blastSource);
    blastSRR(destip, totalfragmask);
    Last_Frag = -1;
    Retry_Timer = MAXRETRYTIME;
  }



}
