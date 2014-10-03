#include <stdio.h>
#include "/proj/netstack/machineInfo.h" // machineInfo struct
#include <stdlib.h>

struct spphdr {
	unsigned char protType;
	unsigned char tinkUID[2];
	unsigned char msgType;
	int saddr;
	int daddr;
};

int main(int argc, char* argv[])
{
  unsigned char ipbroadcastAddr[4] = {255, 255, 255, 255};
  struct spphdr myspphdr;
  unsigned char test[4] = {192, 168, 100, 2};
  int i = 0;
  short ipbc;
  short ip;

  int t = 2;

  printf("t is %x.\n", t >> 2);
  memcpy(&ip, test, 4);
  memcpy(&ipbc, ipbroadcastAddr, 4);
  
  ip = ip | ipbc;

  memcpy(test, &ip, 4);
  
  printf("ip | ipbc = %d \n", ip);

  printf("ip | ipbc = ");
  for(i = 0; i < 4; i++)
	  printf("%d.", test[i])
		  ;
  printf("\n");
printf("For my reference: shorts are %d, unsigned short are %d\n", 
       sizeof(short),
		sizeof(unsigned short));
printf("also, unsigned chars %d, and ints %d\n", sizeof(unsigned char),
		sizeof(int));
 printf("chars are %d.\n", sizeof(char));  
  myspphdr.protType = 33;
  myspphdr.tinkUID[0] = 'g';
  myspphdr.tinkUID[1] = 'k';
  myspphdr.msgType = 0;
  myspphdr.saddr = machineInfo.testIP.s_addr;
  memcpy(&(myspphdr.daddr), ipbroadcastAddr, 4);   

  printf("myspphdr.protType = %d and myspphdr.msgType = %d\n", 
	 myspphdr.protType, myspphdr.msgType);
  printf("myspphdr.saddr = %d and machineInfo.testIP.s_addr = %d\n",
	 myspphdr.saddr, machineInfo.testIP.s_addr);

  printf("printing original source: ");
  memcpy(test, &(machineInfo.testIP.s_addr), 4);
  for (i = 0; i < 4; i++)
    printf("%d.", test[i]);
  printf("\n");

  printf("printing source: ");
  memcpy(test, &(myspphdr.saddr), 4);
  for (i = 0; i < 4; i++)
    printf("%d.", test[i]);
  printf("\n");

  printf("printing dest: ");
  memcpy(test, &(myspphdr.daddr), 4);
  for (i = 0; i < 4; i++)
    printf("%d.", test[i]);
  printf("\n");

return 0;
}
