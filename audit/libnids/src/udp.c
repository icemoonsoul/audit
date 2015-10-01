#include <netinet/udp.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "nids.h"
#include "udp.h"
#include "tcp.h"
#include "checksum.h"
#include "hash.h"
#include "util.h"


/* udp procs */
extern struct proc_node *udp_procs;

/* hash table for udp streams */
static struct udp_stream **udp_stream_table;

/* the pointer to the stored address*/
static struct udp_stream *udp_streams_pool;

/* the size of hash table of the udp streams */
static int udp_stream_table_size;

/* upper bound of the number of the udp streams */
static int udp_max_stream;

/* the total number of the udp streams currently */
static int udp_num = 0;

/* the most latest and oldest udp streams */
static struct udp_stream *udp_latest = 0, *udp_oldest = 0;

/* the free list of the udp stream currently */
static struct udp_stream *udp_free_streams;

static void insert_udp_stream_to_hash(struct tuple4 *addr, struct udp_stream *a_udp)
{
	int hash_index;
	struct udp_stream *tolink;

	hash_index = mk_hash_index(*addr);
	a_udp->next_node = udp_stream_table[hash_index];
	udp_stream_table[hash_index] = a_udp;
}

static void remove_udp_stream_from_hash(struct udp_stream *a_udp)
{
	if(a_udp->pre_node)
		a_udp->pre_node->next_node = a_udp->next_node;
	else
		udp_stream_table[a_udp->hash_index] = a_udp->next_node;
	if(a_udp->next_node)
		a_udp->next_node->pre_node = a_udp->pre_node;
}

static void release_udp_stream(struct udp_stream *udp)
{
	udp->next_free = udp_free_streams;	
	udp_free_streams = udp;
}

static void nids_free_udp_stream(struct udp_stream *a_udp)
{
	int hash_index = a_udp->hash_index;
	struct lurker_node *i, *j;

	remove_udp_stream_from_hash(a_udp);

#if 0
	/* free packet data */
	if(a_udp->client.data)
		free(a_udp->client.data);
				
	if(a_udp->server.data)
		free(a_udp->server.data);
#endif

	/* modify stream list sorted by time */
	if(a_udp->next_time)
		a_udp->next_time->prev_time = a_udp->prev_time;
	
	if(a_udp->prev_time)
		a_udp->prev_time->next_time = a_udp->next_time;
	
	if(a_udp == udp_oldest)
		udp_oldest = a_udp->prev_time;
	
	if(a_udp == udp_latest)
		udp_latest = a_udp->next_time;
	
	i = a_udp->listeners;

	while(i) {
		j = i->next;		
		free(i);
		i = j;
	}

	release_udp_stream(a_udp);

	udp_num--;
}

int
udp_init(int size)
{
	int i;

	if(!size) return 0;

	udp_stream_table_size = size;
	udp_stream_table = calloc(udp_stream_table_size, sizeof(char *));

	if( !udp_stream_table) {
    	nids_params.no_mem("udp_init");
    	return -1;
  	}

  	udp_max_stream = 3 * udp_stream_table_size / 4;
  	udp_streams_pool = (struct udp_stream *) malloc((udp_max_stream + 1) * sizeof(struct udp_stream));
  	
	if( !udp_streams_pool) {
    	nids_params.no_mem("udp_init");
    	return -1;
  	}
  	
	for(i = 0; i < udp_max_stream; i++) {
    	udp_streams_pool[i].next_free = &(udp_streams_pool[i + 1]);
	}

  	udp_streams_pool[udp_max_stream].next_free = 0;
 	udp_free_streams = udp_streams_pool;

	return 0;
}

void udp_exit(void)
{
	int i;
	struct lurker_node *j;
	struct udp_stream *a_udp, *t_udp;

	if( !udp_stream_table || !udp_streams_pool)
		return;
	
	for(i = 0; i < udp_stream_table_size; i++) {
		a_udp = udp_stream_table[i];		
		while(a_udp) {
			t_udp = a_udp;		
			a_udp = a_udp->next_node;
			for(j = t_udp->listeners; j; j = j->next) {
				t_udp->nids_state = NIDS_EXITING;		
				(j->item)(t_udp, &j->data);
			}
			nids_free_udp_stream(t_udp);
		}
	}

	free(udp_stream_table);
	udp_stream_table = NULL;

	free(udp_streams_pool);
	udp_streams_pool = NULL;

	udp_latest = udp_oldest = NULL;
	udp_num = 0;
}

static struct udp_stream *
add_new_udp(struct udphdr *this_udphdr, struct ip *this_iphdr)
{
	struct udp_stream *a_udp;	
	struct udp_stream *tolink;	
	int hash_index;
	struct tuple4 addr;

	addr.source = ntohs(this_udphdr->uh_sport);
	addr.dest = ntohs(this_udphdr->uh_dport);
	addr.saddr = ntohl(this_iphdr->ip_src.s_addr);
	addr.daddr = ntohl(this_iphdr->ip_dst.s_addr);

	hash_index = mk_hash_index(addr);

	if(udp_num > udp_max_stream) {
		struct lurker_node *i;			
		udp_oldest->nids_state = NIDS_TIMED_OUT;
		for(i = udp_oldest->listeners; i; i = i->next) {
			(i->item)(udp_oldest, &i->data);		
		}
		nids_free_udp_stream(udp_oldest);
	}

	a_udp = udp_free_streams;
	udp_free_streams = a_udp->next_free;
	memset(a_udp, 0, sizeof(struct udp_stream));

	udp_num++;

	tolink = udp_stream_table[hash_index];
	memset(a_udp, 0, sizeof(struct udp_stream));
	a_udp->hash_index = hash_index;
	a_udp->addr = addr;
	a_udp->next_node = tolink;
	a_udp->pre_node = NULL;
    /* 2014.10.6 */
    a_udp->client.traffic_count = 0;
    a_udp->server.traffic_count = 0;

	if(tolink)
		tolink->pre_node = a_udp;

	udp_stream_table[hash_index] = a_udp;
	a_udp->next_time = udp_latest;
	a_udp->prev_time = NULL;

	if( !udp_oldest)
		udp_oldest = a_udp;
	if(udp_latest)
		udp_latest->prev_time = a_udp;
	udp_latest = a_udp;

	return a_udp;
}

struct udp_stream *
nids_find_udp_stream(struct tuple4 *addr)
{
	int hash_index;
  	struct udp_stream *a_udp;

  	hash_index = mk_hash_index(*addr);
  	for(a_udp = udp_stream_table[hash_index]; \
			a_udp && memcmp(&a_udp->addr, addr, sizeof(struct tuple4));
    	a_udp = a_udp->next_node);
  	return a_udp ? a_udp : 0;
}

struct udp_stream *
find_udp_stream(struct udphdr *this_udphdr, struct ip *this_iphdr, int *from_client)
{
	struct tuple4 this_addr;
	struct udp_stream *a_udp;

	this_addr.source = ntohs(this_udphdr->uh_sport);
	this_addr.dest = ntohs(this_udphdr->uh_dport);
	this_addr.saddr = ntohl(this_iphdr->ip_src.s_addr);
	this_addr.daddr =ntohl(this_iphdr->ip_dst.s_addr);

	a_udp = nids_find_udp_stream(&this_addr);
	if (a_udp) {
		*from_client = 1;
		return a_udp;
	}

	this_addr.source = ntohs(this_udphdr->uh_dport);
	this_addr.dest = ntohs(this_udphdr->uh_sport);
	this_addr.saddr = ntohl(this_iphdr->ip_dst.s_addr);
	this_addr.daddr = ntohl(this_iphdr->ip_src.s_addr);

	a_udp = nids_find_udp_stream(&this_addr);
	if(a_udp) {
		*from_client = 0;
		return a_udp;
	}

	*from_client = 1;
	return NULL;
}

static struct udp_stream *allocate_udp_stream()
{
	struct udp_stream *udp;
	if( !udp_free_streams)
		return NULL;
	udp = udp_free_streams;	
	udp_free_streams = udp_free_streams->next_free;
	return udp;
}



/*
 * like tcp, ip address is network sequence, and port is host sequence.
 * @data: from ip header
 */
void process_udp(char *data)
{
    struct proc_node *ipp = udp_procs;
    struct ip *iph = (struct ip *) data;
    struct udphdr *udph;
    struct tuple4 addr;
    int hlen = iph->ip_hl << 2;
    int len = ntohs(iph->ip_len);
    int ulen;
	struct udp_stream *a_udp;
	struct lurker_node *j;
	void *app_data;
	int from_client = 0;

	/* verify packet validity */
    if( len - hlen < (int)sizeof(struct udphdr))
		return;

    udph = (struct udphdr *)(data + hlen);
    ulen = ntohs(udph->uh_ulen);

    if (len - hlen < ulen || ulen < (int)sizeof(struct udphdr))
		return;
    /* According to RFC768 a checksum of 0 is not an error (Sebastien Raveau) */
	/* don't check sum */
#if 0
    if (udph->uh_sum && my_udp_check((void *) udph, ulen, \
		iph->ip_src.s_addr,iph->ip_dst.s_addr)) 
		return;
#endif

    addr.source = ntohs(udph->uh_sport);
    addr.dest = ntohs(udph->uh_dport);
    addr.saddr = ntohl(iph->ip_src.s_addr);
    addr.daddr = ntohl(iph->ip_dst.s_addr);

	app_data = (char *)udph + sizeof(struct udphdr);
	
	a_udp = find_udp_stream(udph, iph, &from_client);
	
	if( !a_udp) {
		a_udp = add_new_udp(udph, iph);

		a_udp->nids_state = NIDS_JUST_EST;

		a_udp->server.count_new = ulen - sizeof(struct udphdr);
		a_udp->server.data = app_data;
        /* 2014.10.6 */
        a_udp->server.traffic_count += htons(iph->ip_len);

		a_udp->client.count_new = 0;
		a_udp->client.data = NULL;

		for(; ipp; ipp = ipp->next) {
			void *p = NULL;
			char whatto = 0;
			char cc = a_udp->client.collect;
			char sc = a_udp->server.collect;

			ipp->item(a_udp, &p);
			if(cc < a_udp->client.collect)
				whatto |= COLLECT_cc;

			if (sc < a_udp->server.collect)
				whatto |= COLLECT_sc;

			/* add to listeners */
			if(whatto) {
				j = mknew(struct lurker_node);
				j->item = ipp->item;
				j->data = p;
				j->whatto = whatto;
				j->next = a_udp->listeners;
				a_udp->listeners = j;
			}
		}

		a_udp->nids_state = NIDS_DATA;

#if 0
		if( !a_udp->listeners) {
	    	nids_free_udp_stream(a_udp);
		}
#endif

		return;
	}

	if(from_client) {
		a_udp->server.count_new = ulen - sizeof(struct udphdr);
		a_udp->server.data = app_data;

        /* 2014.10.6 */
        a_udp->server.traffic_count += htons(iph->ip_len);

		a_udp->client.count_new = 0;
		a_udp->client.data = NULL;
	} else {
		a_udp->client.count_new = ulen - sizeof(struct udphdr);
		a_udp->client.data = app_data;

        /* 2014.10.6 */
        a_udp->client.traffic_count += htons(iph->ip_len);

		a_udp->server.count_new = 0;
		a_udp->server.data = NULL;
	}

	/* udp data */
	for(j = a_udp->listeners; j; j = j->next) {
		(j->item)(a_udp, &j->data);
	}

	return;
}
