// compile gcc -o tunfilter main.c -lcidr
// run ./tunfilter -i tun1 -d
/*

TODO:

*implement quic connection recognition https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-quic.c as currently it  limits all udp traffic
*auto setup/ cleanup tun interface
*implement proper tcp connect sequence tracing and timeouts 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <libcidr.h>
#include <time.h>
#include <netdb.h>	

#define BUFSIZE 2000   
#define RULE_TYPE_TIME 1   

#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17
#define PROTOCOL_ICMP 1

#define DIR_REQUEST 1
#define DIR_RESPONSE 2

int debug;
char *progname;

typedef struct 
{
  char address[255];	
  uint32_t netstart;
  uint32_t netend ;
  int type;
  uint32_t amount;
  int time;	
  int timeused;
} rule;

rule *arr_rules=NULL;
int rules_cnt = 0;

typedef struct 
{
  uint32_t adest;
  int pdest;
  int psrc;
  int protocol;
  uint32_t amount;
  uint32_t startTime;
  int finCount;/// count fin packets
  int timeUsed;
} conn_data;

conn_data *arr_conn=NULL;  
int conn_cnt;

/**************************************************************************
* getTick: Retrieves the number of milliseconds that have elapsed since   *
*           the system was started                                        *
**************************************************************************/ 
   
uint32_t getTick() {
  struct timespec ts;
  unsigned theTick = 0U;
  clock_gettime( CLOCK_REALTIME, &ts );
  theTick  = ts.tv_nsec / 1000000;
  theTick += ts.tv_sec * 1000;
  return theTick;
}
 
/**************************************************************************
* print_ip: Print IP in readable format                                   *
**************************************************************************/ 
void print_ip(unsigned int ip)
{
  unsigned char bytes[4];
  bytes[0] = ip & 0xFF;
  bytes[1] = (ip >> 8) & 0xFF;
  bytes[2] = (ip >> 16) & 0xFF;
  bytes[3] = (ip >> 24) & 0xFF;   
  printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);        
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug) {
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename>  [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

/**************************************************************************
 * usage: helps recalculate TCP checksum                                  *
 **************************************************************************/
static uint16_t check2(struct iovec *iov, int iovcnt) {
  long    sum;
  uint16_t    answer;
  struct iovec   *iovp;
  sum = 0;
  for (iovp = iov; iovp < iov + iovcnt; iovp++) {
    uint16_t *ptr;
    size_t len;

    ptr = iovp->iov_base;
    len = iovp->iov_len;

    while (len > 1) {
      sum += *ptr++;
      len -= 2;
    }
    if (len == 1) {
      u_char t[2];
      t[0] = (u_char)*ptr;
      t[1] = 0;

      sum += (uint16_t)*t;
    }
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;    
  return answer;
}

/**************************************************************************
 * usage: recalculates TCP checksum                                       *
 **************************************************************************/

static void tcpcheck(struct iphdr *iph, struct tcphdr *tcph, size_t len) {
  struct iovec iov[5];

  iov[0].iov_base = &iph->saddr;
  iov[0].iov_len = 4;
  iov[1].iov_base = &iph->daddr;
  iov[1].iov_len = 4;

  u_char  t[2];
  t[0] = 0;
  t[1] = iph->protocol;
  iov[2].iov_base = t;
  iov[2].iov_len = 2;

  uint16_t l;
  l = htons(tcph->doff * 4 + len);
  iov[3].iov_base = &l;
  iov[3].iov_len = 2;

  iov[4].iov_base = tcph;
  iov[4].iov_len = tcph->doff * 4 + len;

  tcph->check = 0;
  tcph->check = check2(iov, sizeof(iov) / sizeof(struct iovec));
}

/**************************************************************************
 * usage: recalculates UDP checksum                                       *
 **************************************************************************/

static void udpcheck(struct iphdr *iph, struct udphdr *udph) {
  struct iovec iov[5];

  iov[0].iov_base = &iph->saddr;
  iov[0].iov_len = 4;
  iov[1].iov_base = &iph->daddr;
  iov[1].iov_len = 4;

  u_char  t[2];
  t[0] = 0;
  t[1] = iph->protocol;
  iov[2].iov_base = t;
  iov[2].iov_len = 2;

  uint16_t l;
  l = udph->len;
  iov[3].iov_base = &l;
  iov[3].iov_len = 2;

  iov[4].iov_base = udph;
  iov[4].iov_len = ntohs(udph->len);

  udph->check = 0;
  udph->check = check2(iov, sizeof(iov) / sizeof(struct iovec));
}

/**************************************************************************
 * usage: recalculates IP checksum                                       *
 **************************************************************************/
static uint16_t ipcheck(uint16_t *ptr, size_t len) {
  uint32_t    sum;
  uint16_t    answer;

  sum = 0;
 
  while (len > 1) {
    sum += *ptr++;
    len -= 2;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
    
  return answer;
}

/**************************************************************************
 * usage: Calculates how many bytes was used for all connections to        *
 *         specified ip                                                   *
 **************************************************************************/
int GetAmountUsedForIp(int32_t conn_ip)
{
  int amount=0;
  for (int j=0; j<conn_cnt;j++)
  {		   	
     if (arr_conn[j].adest==conn_ip)	
     {
      	amount=amount+arr_conn[j].amount;      	
     }
  }	
  return amount;
}

/**************************************************************************
 * usage: Calculates how many time was used for all connections to        *
 *         specified ip                                                   *
 **************************************************************************/
int GetTimeUsedForIp(int32_t conn_ip)
{
  int time=0;
  for (int j=0; j<conn_cnt;j++)
  {		   	
     if (arr_conn[j].adest==conn_ip)	
     {
      	time=time+arr_conn[j].timeUsed;
      	if (arr_conn[j].finCount<2)
      	{
      		time=time+(getTick() - arr_conn[j].startTime);
      	}
     }
  }	
  return time;
}

/**************************************************************************
 * usage: Updates connection status                                       *
 **************************************************************************/
void UpdateConn(int j,  int isSyn, int isFin, ssize_t n)
{
  if (isFin==1)
  {
    arr_conn[j].finCount++;
    if (arr_conn[j].finCount==2)
    {
      arr_conn[j].timeUsed=arr_conn[j].timeUsed+(getTick() - arr_conn[j].startTime);
      arr_conn[j].startTime=getTick(); 
    }  
  }
  if ((isSyn==1)&&(arr_conn[j].finCount==2)) //new conn with same source/dest port 
  {	    	
    arr_conn[j].startTime=getTick(); 
    arr_conn[j].finCount=0;
  }
  arr_conn[j].amount=arr_conn[j].amount+n;	
}


/**************************************************************************
 * usage: Adds connection to connection list                              *
 **************************************************************************/
void AddConn(int32_t ip_tocheck, int pdest, int psrc, int isSyn, int isFin, int protocol , ssize_t n)
{
  arr_conn=(conn_data*)realloc(arr_conn, (conn_cnt+1)*sizeof(conn_data));
  arr_conn[conn_cnt].adest=ip_tocheck;
  arr_conn[conn_cnt].timeUsed=0;
  arr_conn[conn_cnt].pdest=pdest;
  arr_conn[conn_cnt].psrc=psrc;
  arr_conn[conn_cnt].protocol=protocol;  
  arr_conn[conn_cnt].startTime=getTick();        
  arr_conn[conn_cnt].amount=0;
  conn_cnt++;
  do_debug("appended connection list \n","");
}

/**************************************************************************
 * usage: Checks if packet needs to be dropped by any rule                *
 **************************************************************************/
int checkRules(int32_t ip_tocheck, int pdest, int psrc, int isSyn, int isFin, int protocol , ssize_t n)
{
  int DropPacket=0;
  int conn_updated=0;    	
  for (int i=0; i<rules_cnt;i++)
  {
    if (( ip_tocheck >= arr_rules[i].netstart)&& (ip_tocheck <= arr_rules[i].netend))
    {
      int conn_found = 0;
      for (int j=0; j<conn_cnt;j++)
      {		   	
        if ((arr_conn[j].adest==ip_tocheck)&&(arr_conn[j].pdest==pdest)&&(arr_conn[j].psrc==psrc)) 
	{
	  conn_found=1;
	  if (conn_updated==0)
	  {
	     UpdateConn( j, isSyn, isFin, n);
	     conn_updated=1;
	  }	
	  	   	 	
	  if ( arr_rules[i].type==RULE_TYPE_TIME)
	  {  
	    if ((GetTimeUsedForIp(ip_tocheck)) >  arr_rules[i].time*1000 )
	    {            
             // if (protocol == 17) /*ONLY UDP*/
            //  {
                DropPacket=1;  
                do_debug("Packet will be dropped by rule # %d \n",i+1);
            //  }              
            }			   	      	
          }
          else// data amount
          {            
            if (GetAmountUsedForIp(ip_tocheck)>arr_rules[i].amount)
            {
              DropPacket=1;
              do_debug("Packet will be dropped by rule # %d \n",i+1);
            }
          }
        }
      }
      if (conn_found==0)//add connection  to list
      {      
        AddConn(ip_tocheck, pdest, psrc, isSyn, isFin, protocol, n);       
      }	   
    }
  }  
  return DropPacket;   
}

/**************************************************************************
 * usage: inspects received packet and decides if packet needs to be      *
 *         dropped                                                        *
 **************************************************************************/
static int InspectPacket(u_char* buf, ssize_t n, u_char* net1, u_char* net2) {
  struct iphdr   *iph;
  size_t      len;
  struct tcphdr  *tcph=NULL;     
  struct udphdr  *udph=NULL; 

  iph = (struct iphdr*)(buf  );
  len = iph->ihl * 4;

  int pdest;
  int psrc;
  int isSyn = 0;
  int isFin = 0;
  if (iph->protocol == PROTOCOL_TCP)
  {
    do_debug("TCP \n","");   
    tcph = (struct tcphdr*)((u_char*)iph + len);    
    pdest=ntohs(tcph->dest);
    psrc=ntohs(tcph->source);    
    isSyn=tcph->syn;
    isFin=tcph->fin;    
  }
  else if (iph->protocol == PROTOCOL_UDP)
  {
    do_debug("UDP \n","");   
    udph = (struct udphdr*)((u_char*)iph + len);
    pdest=ntohs(udph->dest);
    psrc=ntohs(udph->source);    
  }
  else if (iph->protocol == PROTOCOL_ICMP)
  {
    do_debug("ICMP \n","");
  }
  else  
  {
    do_debug("Other protocol=%d \n",iph->protocol);
  }
  
  /* clear crc */
  iph->check = 0;
  
  //print_ip(iph->daddr);
  //print_ip(iph->saddr); 
  //do_debug("source port  %d \n",psrc);    
  //do_debug("dest port %d \n",pdest);
  //do_debug("syn %d \n",isSyn);
  //do_debug("fin %d \n",isFin); 
  
  int direction; // 1- to server; 2 from server
  /* replcace ip */
  if (memcmp(&iph->saddr, net1, 4)) 
  {
    memcpy(&iph->saddr, net2, 4);
    direction = DIR_REQUEST;
  }

  if (memcmp(&iph->daddr, net2, 4)) 
  {
    memcpy(&iph->daddr, net1, 4);
    direction = DIR_RESPONSE;
  }  
        
  int32_t ip_tocheck;    	
  
  if (direction == DIR_REQUEST)
  {
    ip_tocheck=iph->daddr;      	
  }
  else
  {
    ip_tocheck=iph->saddr;    
    int tmp;
    tmp=pdest;
    pdest=psrc;
    psrc=tmp;
  }

  int DropPacket=checkRules( ip_tocheck, pdest, psrc, isSyn, isFin, iph->protocol, n);

  /* put new crc */
  iph->check = ipcheck((uint16_t*)iph, len);
         
  if (iph->protocol == PROTOCOL_TCP) 
  {
    tcpcheck(iph, tcph, n - ((u_char*)tcph - buf) - tcph->doff * 4);    
  }  
  else if (iph->protocol == PROTOCOL_UDP)
  {
    udpcheck(iph, udph);
  }  	

  return DropPacket;
}

/**************************************************************************
 * usage: resolves host name to ip address                                *
 **************************************************************************/

int hostname_to_ip(char * hostname , char* ip)
{
  struct hostent *he;
  struct in_addr **addr_list;
  int i;
		
  if ( (he = gethostbyname( hostname ) ) == NULL) 
  {
    // get the host info
    herror("gethostbyname");
    return 1;
  }
  addr_list = (struct in_addr **) he->h_addr_list;
	
  for(i = 0; addr_list[i] != NULL; i++) 
  {
    //Return the first one;
    strcpy(ip , inet_ntoa(*addr_list[i]) );
    return 0;
  }
  return 1;
}

/**************************************************************************
 * usage: Resolves rule type and amount                                   *
 **************************************************************************/

void resolve_rule_type_amt( rule * record, char type[32], char amount[32] )
{
  int multiplier=1;
  if (strcmp(type,"s")==0)
  {
    record->type=1;
    multiplier=1;
  }
  else  if (strcmp(type,"m")==0)
  {
    record->type=1;
    multiplier=60;
  }
  else  if (strcmp(type,"h")==0)
  {
    record->type=1;
    multiplier=60*60;
  }
  else  if (strcmp(type,"kb")==0)
  {
    record->type=2;
    multiplier=1024;
  }
  else  if (strcmp(type,"mb")==0)
  {
    record->type=2;
    multiplier=1024*1024;
  }
  else  if (strcmp(type,"gb")==0)
  {
    record->type=2;
    multiplier=1024*1024*1024;
  }
  else
  {  
    do_debug("Incorrect Rule Type '%s'\n", type);
    my_err("Incorrect rule !\n");
  }
  
  if (record->type==1)
  {  
    record->time=atoi(amount)*multiplier;  
  }
  else
  {
    record->amount = atoi(amount)*multiplier;     
  }  

}

/**************************************************************************
 * usage: Print rule record                                               *
 **************************************************************************/

void print_rule(rule * record)
{
  do_debug("address %s\n", record->address);
  do_debug("netstart %d\n", record->netstart);
  do_debug("netend %d\n", record->netend);
  do_debug("type %d\n", record->type);
  do_debug("amount %d\n", record->amount);
  do_debug("time %d\n", record->time);
}

/**************************************************************************
 * usage: checks if string contains any letters                           *
 **************************************************************************/

int string_contains_letters( char str[255])
{
  int letters_found = 0;
  int len = strlen(str);
  for(int i = 0; i < len; i++) 
  {
    if((str[i]>=96)&&(str[i]<132)) // letters
    {
      letters_found = 1;
      break;
    }
  }  
  return letters_found; 
}
/**************************************************************************
 * usage: reads rules file to memory                                      *
 **************************************************************************/
int load_rules()
{
  FILE * frules;
  char * line = NULL;
  size_t len = 0;
  ssize_t read;  
  char delim[] = " ";
  frules = fopen("rules", "r");
  if (frules == NULL)
    do_debug("can't open rules file", "");
  
  arr_rules = NULL;
    
  while ((read = getline(&line, &len, frules)) != -1) 
  {
    
    arr_rules=( rule*)realloc(arr_rules, (rules_cnt+1)*sizeof( rule));
  
    char *ptr = strtok(line, delim);        
    strcpy(arr_rules[rules_cnt].address, ptr);      
    ptr = strtok(NULL, delim);
    char amount[32]= "";
    char type[32]= "";   
    int i;

    len = strlen(ptr+1);   
    
    for(i = 0; i < len; i++) 
    {
      if((ptr[i]>47)&&(ptr[i]<57)) // nubers
      {
        amount[i]=ptr[i];
      }
      else
      {
        type[i-strlen(amount)]=ptr[i];
      }   
    }   

    resolve_rule_type_amt(&arr_rules[rules_cnt], type, amount);    
    
    if (string_contains_letters(arr_rules[rules_cnt].address)==1)
    {
      hostname_to_ip(arr_rules[rules_cnt].address,arr_rules[rules_cnt].address);
    }
      
    CIDR *addr1;
    addr1 = cidr_from_str(arr_rules[rules_cnt].address);   

    uint32_t netip =0; // network ip to compare with
    uint32_t netmask=0 ; // network ip subnet mask
        
    inet_pton(AF_INET, cidr_to_str(addr1, CIDR_ONLYADDR ), &netip);
    inet_pton(AF_INET, cidr_to_str(addr1, CIDR_ONLYPFLEN | CIDR_NETMASK), &netmask);
        
    arr_rules[rules_cnt].netstart = (netip & netmask); // first ip in subnet
    arr_rules[rules_cnt].netend = (arr_rules[rules_cnt].netstart | ~netmask); // last ip in subnet
   // print_rule(&arr_rules[rules_cnt]);
    rules_cnt++;      
  }

  fclose(frules); 
  return rules_cnt;
}

/**************************************************************************
 * usage: Main function                                *
 **************************************************************************/

int main(int argc, char *argv[]) {
  
  int tun_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];  
  u_char  buf[15000];
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  unsigned long int packets_read = 0, packets_send = 0;
  u_char net1[] = {192, 168, 5, 1};
  u_char net2[] = {192, 168, 5, 2};
  progname = argv[0]; 
    
  /* Check command line options */
  while((option = getopt(argc, argv, "i:hd")) > 0) {
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg, IFNAMSIZ-1);
        break;       
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }
  argv += optind;
  argc -= optind;

  if(argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  } 
  
  do_debug("Loading rules\n", "");
  load_rules();
  do_debug("%d rules loaded \n", rules_cnt);
 
  do_debug("Connecting to interface %s\n", if_name);
   
  /* initialize tun/tap interface */
  if ( (tun_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }
  do_debug("Successfully connected to interface %s\n", if_name);
  
  do_debug("Starting To Read \n", "");
  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tun_fd, &rd_set);

    ret = select(tun_fd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tun_fd, &rd_set)) {
      /* data from tun: just read it and write it to the network */
      
      nread = cread(tun_fd, buffer, BUFSIZE);

      packets_read++;
      do_debug("# %lu: Read %d bytes from the tun interface\n", packets_read, nread);


      if (InspectPacket(buffer, nread, net1, net2)==0) {        
        nwrite = cwrite(tun_fd, buffer, nread);
	packets_send++;
	do_debug("# %lu: Written %d bytes to the tun interface\n", packets_send, nwrite);
      }     
    }      
  } 
  return(0);
}
