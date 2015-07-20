#include "veridp.h"
#include "veridp_topo.h"

#include "lib/flow.h"  /*2015-4-4 ZP add: to use function flow_extract()*/
#include "lib/flow.c"  /*2015-4-4 ZP add: to use function flow_extract()*/
#include "csum.h"

#include <sys/socket.h>  /*udp socket*/
#include <arpa/inet.h>

#include <sys/param.h>	/*crc32*/ 

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


int d = 0 ;
//-----------UDP send to VeriDP server------------//
#define PORT 1111                   /*VeriDP server addr*/
#define SERVER_IP "192.168.2.99"   /*VeriDP server addr*/
static struct sockaddr_in addr;
static int addr_b_size = sizeof(struct sockaddr_in);

struct payload{
    uint16_t tag;
    uint8_t ip_proto;
    uint16_t trans_src;
    uint16_t trans_dst;
    uint32_t ip_src;
    uint32_t ip_dst;        
};


//-----------CRC32.c-------------//
/*-
 *  COPYRIGHT (C) 1986 Gary S. Brown.  
 *  The polynomial is
 *  X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+X^8+X^7+X^5+X^4+X^2+X^1+X^0 
 */
static uint32_t crc32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t crc32(uint32_t crc, const void *buf, size_t size){
    const uint8_t *p;
    p = buf;
    crc = 0xffffffff;  //crc = crc ^ ~0U;

    while (size--)
        crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

    return ~crc;    //return crc ^ ~0U;
};

/* inport||switchID||outport */
uint16_t calculate_crc32_hash(struct packet *pkt){
    uint32_t in_port_no = pkt->in_port;
    uint32_t out_port_no = pkt->out_port;
    uint64_t datapath_id = pkt->dp->id;

    uint32_t hash32 = 0;
    uint16_t hash16;

    size_t data_size = sizeof(in_port_no) + sizeof(out_port_no) + sizeof(datapath_id);
    uint8_t data[data_size];
    uint8_t *p = &data[0];

    memcpy(p, &datapath_id, sizeof(uint64_t));
    memcpy(p + 8, &in_port_no, sizeof(uint32_t));
    memcpy(p + 12, &out_port_no, sizeof(uint32_t));

    hash32 = crc32(hash32, p, data_size);
    hash16 = hash32 & 0xffff;  /*Get the lower 16 bit of hash32*/
    printf("        Function:calculate_crc32_hash() = %lu\n", hash16);
    return hash16;
};


//----------TAG MUDULE-----------//
/* push the 16-bits VeriDP TAG to the packet. FIXME! */
static void
dp_push_vdp_tag(struct packet *pkt) {
   
   return;
}

/* Get the 16-bits VeriDP TAG of the packet, as return valnue.
 * Note this must be called after pkt buffer be extracted.
 * For tcp, tag is at the 21th byte of header.
 * For udp, tag is at the 9th byte of header. 
 * return in host byte order.
 */
static uint16_t
dp_get_vdp_tag(struct packet *pkt ) {
    uint16_t tag = 0;
    if ( is_edge_port(pkt->dp->id, pkt->in_port) == false) {
	    uint8_t *p4;
	    p4 = (uint8_t*)pkt->buffer->l4;
	    if (pkt->handle_std->proto->ipv4->ip_proto == 6) {
		    memcpy(&tag, &p4[20], 2);
		}
		else if(pkt->handle_std->proto->ipv4->ip_proto == 17)
		{
			memcpy(&tag, &p4[8], 2);
		}
    }
    print_a_bucket("\tdp_get_vdp_tag:", (uint8_t *)&tag, 2);
    return ntohs(tag);
}

static void send_tag_in_udp(struct packet *pkt){
    uint16_t p_tag       = dp_get_vdp_tag(pkt);
    uint32_t p_ip_src    = pkt->handle_std->proto->ipv4->ip_src;
    uint32_t p_ip_dst    = pkt->handle_std->proto->ipv4->ip_dst;
    uint8_t p_ip_proto   = pkt->handle_std->proto->ipv4->ip_proto;
    uint16_t p_trans_src;
    uint16_t p_trans_dst;
    if (p_ip_proto == 6) {
	    p_trans_src = pkt->handle_std->proto->tcp->tcp_src;
	    p_trans_dst = pkt->handle_std->proto->tcp->tcp_dst;
	    printf("\tTCP:%x\n", p_ip_proto);
    }else if (p_ip_proto == 17)
    {
	    p_trans_src = pkt->handle_std->proto->udp->udp_src;
	    p_trans_dst = pkt->handle_std->proto->udp->udp_dst;
	    printf("\tUDP:%x\n", p_ip_proto);
    }

    struct payload n_data;
    memset(&n_data, 0, sizeof(n_data));
    n_data.tag        = htons(p_tag);
    n_data.ip_proto   = p_ip_proto;
    n_data.trans_src  = htons(p_trans_src);
    n_data.trans_dst  = htons(p_trans_dst);
    n_data.ip_src     = htonl(p_ip_src);
    n_data.ip_dst     = htonl(p_ip_dst);

    bzero(&addr,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    int skt,skt_send_b_size;
    skt_send_b_size = 16;
    uint8_t buffer[16];

    /* prepare buffer */
    memcpy(buffer, &n_data, sizeof(n_data));
    printf("\tUDP Buffer is:\n");
    int i;
    for (i = 0; i < 16; ++i) {
        printf("%02x ",   buffer[i]);
    }
    printf("\n");

    /* create a socket */
    if( (skt = socket(AF_INET,SOCK_DGRAM,0)) < 0 ){
        printf("creat socket error\n");
        perror("socket");
        exit(1);
    }
    /* SEND the data to server */
    sendto(skt, buffer, skt_send_b_size, 0, (struct sockaddr *)&addr,addr_b_size);
    printf("Sending... OK.\n\n\n\n");
}
    
void print_pkt_buffer(struct packet *pkt ){
    int i;
    uint8_t *p; 

    p = (uint8_t *)pkt->buffer->data; 
    size_t allocted_size = pkt->buffer->allocated;
    size_t used_size = pkt->buffer->size;

    // printf("\tallocted size =%d\n", allocted_size);
    printf("\tused size     =%d\n", used_size);

    printf("\t&data=%p\n", pkt->buffer->data);
    printf("\t&l2=%p\n", pkt->buffer->l2);
    printf("\t&l3=%p\n", pkt->buffer->l3);
    printf("\t&l4=%p\n", pkt->buffer->l4);
    printf("\t&l7=%p\n", pkt->buffer->l7);

    printf("\tPacket Buffer used size[%%x]:\n");
    for (i = 0; i < used_size; ++i) {
        if (i%32 == 0 && i > 0) printf(" [%d][%p]\n", i, &p[i]);
        printf("%02x ", p[i]);                            
    } 

    p = (uint8_t*)pkt->buffer->l4;
    if (pkt->handle_std->proto->tcp != NULL)
    {
    	printf(" TCPchecksum:%02x %02x; ", p[16], p[17] );
    	printf(" VDPtag:%02x %02x\n", p[20], p[21] );
    }else if (pkt->handle_std->proto->udp != NULL)
    {
    	printf(" UDPchecksum:%02x %02x; ", p[6], p[7] );
    	printf(" VDPtag:%02x %02x", p[8], p[9]);
    }
    
    printf("\n");       
}

void print_a_bucket(char *desc, uint8_t *pStart, int length){
    int i;
    printf("%s", desc);
    for ( i = 0; i < length; ++i)
    {
        if (i > 0 && i%32 == 0) printf(" [%p]\n", &pStart[i]);
        printf("%02x ", pStart[i]);
    }
    printf("\n");
}    



/*----------VDP MODUEL below------------*/
int tag_pkt_num = 0;

int veridp_mudule(struct packet *pkt, uint32_t out_port){ 
	/*extract pkt buffer*/ 
    struct flow flows;
    flow_extract(pkt->buffer, pkt->in_port, &flows);
    print_a_bucket("\tExtreact Flow is this like:", (uint8_t*)&flows, 35);
  
    if (pkt->handle_std->proto->tcp != NULL || pkt->handle_std->proto->udp != NULL)
    {
	    uint8_t pkt_type = 0;
	    pkt_type = pkt->handle_std->proto->ipv4->ip_proto;

	    /*calculate tag*/
	    uint16_t old_tag = 0;
	    uint16_t new_tag = 0;
	    uint16_t n_new_tag;
	    uint16_t hash16_val = 0;
	    pkt->out_port = out_port;
	    hash16_val = calculate_crc32_hash(pkt); 
	    old_tag = dp_get_vdp_tag(pkt);
	    new_tag = old_tag ^ hash16_val;
	    n_new_tag = htons(new_tag);
	    print_a_bucket("======old_tag is:", (uint8_t *)&old_tag, 2);
	    print_a_bucket("======new_tag is:", (uint8_t *)&new_tag, 2);

	    /*put tag to packet, and recalculate checksum*/
	    printf("\tBefore push tag, Print pkt buffer struct:\n");
	    print_pkt_buffer(pkt);
	    if (pkt_type == 6) { 
	   	    uint16_t new_csum = 0;
	   	    uint8_t *p;
		    new_csum = recalc_csum16(pkt->handle_std->proto->tcp->tcp_csum, 
		    						 htons(old_tag), htons(new_tag));
		    pkt->handle_std->proto->tcp->tcp_csum = new_csum;

		    p = (uint8_t*)(pkt->handle_std->proto->tcp);
		    //printf("........p=%p, p[20]=%p, &p[20]=%p\n", p, p[20], &p[20]);
		    memcpy(&p[20], &new_tag , 2);

		}else if(pkt_type == 17)
		{
			uint16_t new_csum = 0;
			uint8_t *p;
			new_csum = recalc_csum16(pkt->handle_std->proto->udp->udp_csum,
									htons(old_tag), htons(new_tag));
			pkt->handle_std->proto->udp->udp_csum = new_csum;
			p = (uint8_t*)(pkt->handle_std->proto->udp);
			memcpy( &p[8], &n_new_tag , 2);
		}
		/*
		    printf("===================\n");
		    printf("pkt->handle_std->proto->ipv4        %p\n", pkt->handle_std->proto->ipv4);
		    printf("pkt->handle_std->proto->ipv4->ip_proto    %p\n", &(pkt->handle_std->proto->ipv4->ip_proto));
		    printf("pkt->handle_std->proto->tcp         %p\n", pkt->handle_std->proto->tcp);
		    printf("pkt->handle_std->proto->tcp->tcp_csum     %p\n", &(pkt->handle_std->proto->tcp->tcp_csum));
		    printf("===================\n");
	    */

	    printf("\tAfter push tag, Print pkt buffer struct:\n");
	    print_pkt_buffer(pkt);

	    printf("\tThis is the NO.%d packet be taged and poped. OUTPORT=%u\n", 
	    						tag_pkt_num++, out_port);
	 
	    if ( /*is_edge_port(pkt->dp,  out_port) */1 ) {                 
	        send_tag_in_udp(pkt);
                                //*
            FILE *fp; 
            fp = fopen("rcd-test-log-sendudp-data.txt","a+"); 
            if (fp == NULL)
            {
                printf("Open record log file error.\n");
            }
            fprintf(fp," send_tag_in_udp Record %d \n", d); 
            d++;
            fclose(fp); //*/ 

	    }  
	}
    return 0;
}
 

    
#if 0
/*---------------------test code--------------*/
    struct flow *flow;
    flow = &flows;
    struct ofpbuf *packet = pkt->buffer;
    struct ofpbuf b = *packet;
    struct eth_header *eth;
    int retval = 0;
    printf("\tofbuf[%p]->data[%p]\n", packet, packet->data);

    memset(flow, 0, sizeof *flow);
    flow->dl_vlan = htons(OFPVID_NONE);
    flow->in_port = htonl(pkt->in_port);

    packet->l2 = b.data;
    packet->l3 = NULL;
    packet->l4 = NULL;
    packet->l7 = NULL;

    eth = pull_eth(&b);
    printf("\teth[%p]\n", eth);//-----eth--------//
    printf("\tofbuf[%p]->data[%p]\n", packet, packet->data);
    if (eth) {
        if (ntohs(eth->eth_type) >= 0x600) {
            /* This is an Ethernet II frame */
            flow->dl_type = eth->eth_type;
        } else {
            /* This is an 802.2 frame */
            struct llc_header *llc = ofpbuf_at(&b, 0, sizeof *llc);
            struct snap_header *snap = ofpbuf_at(&b, sizeof *llc,
                                                 sizeof *snap);
            if (llc == NULL) {
                return 0;
            }
            if (snap
                && llc->llc_dsap == LLC_DSAP_SNAP
                && llc->llc_ssap == LLC_SSAP_SNAP
                && llc->llc_cntl == LLC_CNTL_SNAP
                && !memcmp(snap->snap_org, SNAP_ORG_ETHERNET,
                           sizeof snap->snap_org)) {
                flow->dl_type = snap->snap_type;
                ofpbuf_pull(&b, LLC_SNAP_HEADER_LEN);
            } else {
                flow->dl_type = htons(0x05ff);
                ofpbuf_pull(&b, sizeof(struct llc_header));
            }
        }

        /* Check for a VLAN tag */
        if (flow->dl_type == htons(ETH_TYPE_VLAN)) {
            struct vlan_header *vh = pull_vlan(&b);
            if (vh) {
                flow->dl_type = vh->vlan_next_type;
                flow->dl_vlan = vh->vlan_tci & htons(VLAN_VID_MASK);
                flow->dl_vlan_pcp = (uint8_t)((ntohs(vh->vlan_tci) >> VLAN_PCP_SHIFT)
                                               & VLAN_PCP_BITMASK);
            }
        }
        memcpy(flow->dl_src, eth->eth_src, ETH_ADDR_LEN);
        memcpy(flow->dl_dst, eth->eth_dst, ETH_ADDR_LEN);

        packet->l3 = b.data;
        printf("\tl3[%p]\n", packet->l3);   //------------l3-----------//
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            const struct ip_header *nh = pull_ip(&b);
            printf("\tnh[%p]\n", nh);   //------------l3-----------//
            printf("\tofbuf[%p]->data[%p]\n", packet, packet->data);
            if (nh) {
                flow->nw_tos = nh->ip_tos & 0xfc;
                flow->nw_proto = nh->ip_proto;
                flow->nw_src = nh->ip_src;
                flow->nw_dst = nh->ip_dst;
                packet->l4 = b.data;
                if (!IP_IS_FRAGMENT(nh->ip_frag_off)) {
                    if (flow->nw_proto == IP_TYPE_TCP) {
                        const struct tcp_header *tcp = pull_tcp(&b);
                        if (tcp) {
                            flow->tp_src = tcp->tcp_src;
                            flow->tp_dst = tcp->tcp_dst;
                            packet->l7 = b.data;
                        } else {
                            /* Avoid tricking other code into thinking that
                             * this packet has an L4 header. */
                            flow->nw_proto = 0;
                        }
                    } else if (flow->nw_proto == IP_TYPE_UDP) {
                        const struct udp_header *udp = pull_udp(&b);
                        if (udp) {
                            flow->tp_src = udp->udp_src;
                            flow->tp_dst = udp->udp_dst;
                            packet->l7 = b.data;
                        } else {
                            /* Avoid tricking other code into thinking that
                             * this packet has an L4 header. */
                            flow->nw_proto = 0;
                        }
                    } else if (flow->nw_proto == IP_TYPE_ICMP) {
                        const struct icmp_header *icmp = pull_icmp(&b);
                        if (icmp) {
                            flow->tp_src = htons(icmp->icmp_type);
                            flow->tp_dst = htons(icmp->icmp_code);
                            packet->l7 = b.data;
                        } else {
                            /* Avoid tricking other code into thinking that
                             * this packet has an L4 header. */
                            flow->nw_proto = 0;
                        }
                    }
                } else {
                    retval = 1;
                }
            }
        } else if (flow->dl_type == htons(ETH_TYPE_ARP)) {
            struct arp_eth_header *arp = pull_arp(&b);
            if (arp) {
                if (arp->ar_pro == htons(ARP_PRO_IP) && arp->ar_pln == IP_ADDR_LEN) {
                    flow->nw_src = arp->ar_spa;
                    flow->nw_dst = arp->ar_tpa;
                }
                flow->nw_proto = ntohs(arp->ar_op) & 0xff;
            }
        }
    }
    //--------------------*/
#endif
