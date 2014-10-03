#ifndef SPP_C
#define SPP_C 1

#include "udp.h"

struct spphdr {
  unsigned char protType;
  unsigned char tinkUID[2]; // should be 2 bytes max
  unsigned char msgType; // 8-bits for message type
  int saddr;
  int daddr;
};

struct tinkReport {
  unsigned short uid;
  char ipSource[4];
  char ipDest[4];
};

void sppbroadcast();

void sppsend(unsigned char dest[4], void* data);

void reportToTink(int dest, int src);

void spp_recv(struct udphdr* pMyUDPhdr);

/*
 * sppbroadcast
 */
void sppbroadcast()
{
  unsigned char ipbroadcastAddr[4] = {192, 168, 100, 255};
  struct spphdr* myspphdr = malloc(sizeof(struct spphdr) + 2);
  
  myspphdr->protType = 33;
  myspphdr->tinkUID[0] = 'g';
  myspphdr->tinkUID[1] = 'k';
  myspphdr->msgType = 0;
  myspphdr->saddr = machineInfo.testIP.s_addr;
  memcpy(&(myspphdr->daddr), ipbroadcastAddr, 4);   

  udpsend(ipbroadcastAddr, myspphdr, sizeof(struct spphdr) + 2,
	  2002, 2002);
  free(myspphdr);
}

/*
 * sppsend
 */
void sppsend(unsigned char dest[4], void* data) 
{
  struct spphdr* myspphdr = malloc(sizeof(struct spphdr) + 2);

  myspphdr->protType = 33;
  myspphdr->tinkUID[0] = 'g';
  myspphdr->tinkUID[1] = 'k';
  myspphdr->msgType = 1;
  myspphdr->saddr = machineInfo.testIP.s_addr;
  memcpy(&(myspphdr->daddr), dest, 4);

  udpsend(dest, myspphdr, sizeof(struct spphdr) + 2, 2002, 2002);
  free(myspphdr);
}

/*
 * reportToTink
 */
void reportToTink(int dest, int src)
{
  struct tinkReport* mytinkreport = 
    malloc(sizeof(struct tinkReport) + 8*sizeof(char));
  unsigned char destIP[4] = { 192, 168, 100, 200 }; // Tink
  
  netprintf("SPP Reporting findings to Tink.\n");
  mytinkreport->uid = htons(549);
  memcpy(mytinkreport->ipSource, &src, 4);
  memcpy(mytinkreport->ipDest, &dest, 4);
  
  udpsend(destIP, mytinkreport, sizeof(struct tinkReport) + 8*sizeof(char), 
	  3000, 3000);

  free(mytinkreport);
}

void spp_recv(struct udphdr* pMyUDPhdr)
{
  unsigned char destip[4];
  
    
    int i;
    struct spphdr* pMySPPhdr = (struct spphdr*)(pMyUDPhdr + 1);

    if (pMySPPhdr->protType == 33 && pMySPPhdr->tinkUID[0] == 'g' 
	&& pMySPPhdr->tinkUID[1] == 'k') {
      
      netprintf("SPP Packet received.\n");
      
      if (pMySPPhdr->msgType == 0) { 
	netprintf("SPP Packet recognized for dest port: 2002.\n");
	
	memcpy(destip, &(pMySPPhdr->saddr), 4);
	
	netprintf("SPP source: ");
	
	for (i = 0; i < 4; i++)
	  netprintf("%d.", destip[i]);
	
	memcpy(destip, &(pMySPPhdr->daddr), 4);
	netprintf("\n SPP dest: ");
	
	for (i = 0; i < 4; i++)
	  netprintf("%d.", destip[i]);
	netprintf("\n");
	
	memcpy(destip, &(pMySPPhdr->saddr), 4); 
	
	sppsend(destip, NULL);
	reportToTink(machineInfo.testIP.s_addr, pMySPPhdr->saddr);
	
      } else if (pMySPPhdr->msgType == 1) {
	
	netprintf("SPP Packet reply recognized.\n");
	reportToTink(machineInfo.testIP.s_addr, pMySPPhdr->saddr);
	
      } else {
	netprintf("SPP Packet with unknown msgtype %d.\n", 
		  pMySPPhdr->msgType);
      }
    }
}

#endif // SPP_C
