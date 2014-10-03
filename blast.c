#ifndef BLAST_C 
#define BLAST_C 1

#include "myudp.c" // I need udpsend

#define PROTNUM 42 // My random ProtNum
#define MYMID 42 // My arbitrary MID
#define TYPESRR 2
#define TYPEDATA 1
#define MAXLASTFRAG 3;
#define MAXRETRYTIME 30;
#define SRCREPLYPORT 22299
#define DESTREPLYPORT 22299

struct blasthdr {
  int ProtNum;    // 32-bits for BLAST's prot num
  int MID;        // 32-bits for BLAST's Message ID
  int len;        // 32-bits for BLAST's length of data FOLLOWING header
  
  unsigned short NumFrags; 
                  // 16-bits for number of fragments field
  unsigned short type;     
                  // 16-bits for type of BLAST message (2 SRR or 1 DATA)
  
  int FragMask;   // 32-bits for Fragment mask
};

struct fragment {
  char* contents;
  int len;
};

int Last_Frag = -1; //MAXLASTFRAG;
int totalfragmask = 0;
int blastSource = 0;
int Retry_Timer = -1;
int NumRetries = 0;

int myNumFrags = 0;

struct fragment myfragments[32];

void Last_Frag_Decr()
{
  if (Last_Frag > 0) Last_Frag--;
}

void Last_Frag_Reset()
{
  Last_Frag = MAXLASTFRAG;
}

void blastSRR(unsigned char destIP[4], int mymask)
{
  struct blasthdr* pMyBlastHdr = malloc(sizeof(struct blasthdr));

  pMyBlastHdr->ProtNum = htons(PROTNUM);
  pMyBlastHdr->MID = htonl(MYMID);
  pMyBlastHdr->len = htonl(0); 

  pMyBlastHdr->NumFrags = htons(1);
  pMyBlastHdr->type = htons(TYPESRR);
  
  pMyBlastHdr->FragMask = htonl(mymask);
  
  netprintf("Blasthdr is %d.\n", sizeof(struct blasthdr));

  udpsend(destIP, pMyBlastHdr,
	  sizeof(struct blasthdr), CONNECTPORT, CONNECTPORT);
  
  free(pMyBlastHdr);

  Retry_Timer = MAXRETRYTIME;
}

void blastConnect(unsigned char destIP[4]) 
{
  blastSRR(destIP, 0);
}

void saveFragment(int packetNum, char* contents, int len)
{
  myfragments[packetNum].contents = malloc(len);
  memcpy(myfragments[packetNum].contents, contents, len);
  myfragments[packetNum].len = len;
}

void replyudp()
{
  char* replymsg;
  int count;
  int sizeMsg = 0;
  int position = 0;
  unsigned char destip[] = {192, 168, 100, 200};

  // Get the length of all the fragment data combined.
  for (count = 0; count < myNumFrags; count++) {
    sizeMsg = sizeMsg + myfragments[count].len;
  }

  replymsg = malloc(sizeMsg);

  for (count = 0; count < myNumFrags; count++) {
    memcpy(replymsg + position, 
	   myfragments[count].contents, 
	   myfragments[count].len);
    position = position + myfragments[count].len;
    netprintf("Line %d: %s", count + 1, myfragments[count].contents);
  }

  udpsend(destip, replymsg, sizeMsg, SRCREPLYPORT, DESTREPLYPORT);

  free(replymsg);
}

void blastRecv(struct udphdr* pMyUDPhdr)
{
  struct blasthdr* pMyBlastHdr = (struct blasthdr*)(pMyUDPhdr + 1);
  int packetNum = 0;
  int test = 0;
  int allfrags = 0;
  int count = 0;
  char* contents;
  unsigned char destip[] = {192, 168, 100, 200};
  
  netprintf("Received BLAST packet.\n");

  if (ntohl(pMyBlastHdr->MID) == MYMID) {
    
    if (ntohs(pMyBlastHdr->type) == TYPEDATA) {
      
      for(test = 1; 
	  packetNum < ntohs(pMyBlastHdr->NumFrags) && 
	    (test << packetNum) != ntohl(pMyBlastHdr->FragMask);
	  ) {
	packetNum++;
      }
      
      contents = malloc(ntohl(pMyBlastHdr->len) + 1);

      memcpy(contents, pMyBlastHdr + 1, ntohl(pMyBlastHdr->len));
      contents[ntohl(pMyBlastHdr->len)] = '\0';
      
      netprintf("%d of %d: %s\n", packetNum + 1,
		ntohs(pMyBlastHdr->NumFrags), contents);

      myNumFrags = ntohs(pMyBlastHdr->NumFrags);

      saveFragment(packetNum, contents, ntohl(pMyBlastHdr->len));

      Last_Frag_Reset();
      
      totalfragmask = totalfragmask | ntohl(pMyBlastHdr->FragMask); 
      netprintf("Total Received Fragment Mask: %x.\n", totalfragmask);

      // Check if I just received the last packet
 
      test = 1;

      if ((test << (packetNum + 1)) == test << ntohl(pMyBlastHdr->NumFrags)) {
	netprintf("Received last fragment.\n");
	blastSRR(destip, totalfragmask);
      }

      for (allfrags = 0; count < ntohs(pMyBlastHdr->NumFrags); count++) {
	allfrags = allfrags | (test << count);
      }
  
      if (totalfragmask == allfrags) {
	netprintf("I received all the fragments!\n");
	Last_Frag = -1;
	Retry_Timer = -1;
	replyudp();         // Reply with complete message to tink
	totalfragmask = 0;
      }

      free(contents);
    }
  }
}

#endif // BLAST_C
