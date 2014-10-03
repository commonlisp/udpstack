#ifndef MYUDP_C
#define MYUDP_C 1

#include "ip.c"

void udpsend(unsigned char dest[4], void* data, int len, int srcport,
	     int destport);

/*
 * udpsend
 */
void udpsend(unsigned char dest[4], void* data, int len, int srcport,
	     int destport) 
{
  struct udphdr* myudphdr = malloc(sizeof(struct udphdr) + len);
  
  myudphdr->source = htons(srcport);
  myudphdr->dest = htons(destport);
  myudphdr->len = htons(len + sizeof(struct udphdr));
  myudphdr->check = 0;

  memcpy(myudphdr + 1, data, len);

  //netprintf("UDP Send Length: %d.\n", ntohs(myudphdr->len) + 
  //	    sizeof(struct udphdr));

  ipsend(dest, myudphdr, sizeof(struct udphdr) + len);
  free(myudphdr);
}

#endif // MYUDP_C
