#ifndef ETH_C
#define ETH_C 1

void specialsend(unsigned char dest[6], void* data, int len, 
		 unsigned short protocol);

// Packages and sends a special UDP packet
void specialsend(unsigned char dest[6], void* data, int len, 
		 unsigned short protocol) {

  struct ethHeader* myHdr = malloc(sizeof(struct ethHeader) + len);

  // Set destination and source addresses
  memcpy(myHdr->destaddr, dest, 6);
  
  memcpy(myHdr->srcaddr, machineInfo.testMAC, 6);

  // Set protocol type
  myHdr->type = protocol;

  netprintf("The length of my payload is %d.\n", len);

  // Copy payload
  memcpy(myHdr + 1, data, len);

  netsend(myHdr, sizeof(struct ethHeader) + len);
  
}

#endif // ETH_C
