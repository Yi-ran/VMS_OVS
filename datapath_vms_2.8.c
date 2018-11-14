/*
 * Copyright (c) 2007-2015 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/etherdevice.h>
#include <linux/genetlink.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/wait.h>
#include <asm/div64.h>
#include <linux/highmem.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/openvswitch.h>
#include <linux/rculist.h>
#include <linux/dmi.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "datapath.h"
#include "conntrack.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "gso.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

/*start of Yiran's structure*/
#include <linux/hashtable.h>
#include <linux/skbuff.h>
#include <linux/limits.h>
#include <linux/jiffies.h>
#include <linux/param.h>
#include <net/tcp.h>
#include <linux/timer.h>
#define NONE 0
#define LEFT 1
#define RIGHT 2
#define BRIDGE_NAME "br0" //help determine the direction of a packet, when we move to container, we only compare first 2 char
#define OVS_PACK_HEADROOM 32
#define MSS_DEFAULT 1400U
#define TBL_SIZE 12U
//#define RWND_INIT 1400U
#define RWND_INIT 2800U
#define RWND_MIN (MSS)
#define RWND_STEP (MSS)
#define RWND_CLAMP (10*1000*1000*4/8) //4 means the maximal latency expected (4 msec), in bytes
//#define RWND_SSTHRESH_INIT ULONG_MAX
#define RWND_SSTHRESH_INIT 0xFFFFFFFFUL
#define DCTCP_ALPHA_INIT 1024U
#define DCTCP_MAX_ALPHA  1024U
static unsigned int MSS = MSS_DEFAULT;
module_param(MSS, uint, 0644);
MODULE_PARM_DESC(MSS, "An unsigned int to initlize the MSS");

static unsigned int ECE_CLEAR = 0;
module_param(ECE_CLEAR, uint, 0644);
MODULE_PARM_DESC(ECE_CLEAR, "An unsigned int to initlize the ECE_CLEAR--whether clear the ECE bit in ACK");

static unsigned int dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(dctcp_shift_g, uint, 0644);
MODULE_PARM_DESC(dctcp_shift_g, "parameter g for updating dctcp_alpha");

bool is_init = false;
int first = 1;

unsigned int seed = 10;

static struct timer_list my_timer;
enum {
        OVS_VMS_ENABLE = 1U,
        OVS_VMS_CLEAR = 14U,
        OVS_VMS_CHANNEL = 7U,
        VMS_CHANNEL_NUM = 8,
        CHANNEL_NUM_INDEX = 3,
        VMS_CHANNEL_RCE = 1U,
        VMS_CHANNEL_RCE_CLEAR = 254U,
        VMS_SIN_FLAG = 2U,  
        OVS_ECN_MASK = 3U,
        OVS_ECN_ZERO = 0U,
        OVS_ECN_ONE = 1U, 
};


//hashtable and spinlock
static DEFINE_SPINLOCK(datalock);
static DEFINE_SPINLOCK(acklock);
static DEFINE_HASHTABLE(rcv_data_hashtbl, TBL_SIZE);
static DEFINE_HASHTABLE(rcv_ack_hashtbl, TBL_SIZE);
/*
|       |     |V|F|S|           |
|Length | cID |M|B|I|    Flags  |
|_ _ _ _|_ _ _|S|K|N|_ _ _ _ _ _|
  4        3      3        6
        |tcpres1|
         
FBK  -------> CWR
SIN  -------> ECE
*/

struct ListNode {
	u32 seq;
	u32 tcp_data_len;
	struct sk_buff  *skb;
	struct ListNode		*next;
};

//record  which channel the packet choose, used for packet loss recovery
//assume the sender always sends packets in order except the retransmission packet. 
struct SeqNode {
    u32 seq;
    u8 cid;
    struct SeqNode     *next;
};

struct SeqChain
{
    struct SeqNode *head;
    struct SeqNode *tail;
};



typedef struct TreeNode
{
    struct ListNode        *head;
    struct ListNode        *tail;
    struct TreeNode        *left;
    struct TreeNode        *right;
    struct TreeNode	       *parent;
    u8 type;
}*pnode;

struct ChannelInfo {
	u32 receivedCount;
	u32 rwnd;			
	u32 rwnd_ssthresh;
	u32 rwnd_clamp;
	u32 alpha;
	u32 LocalSendSeq;
	u32 LocalRecvSeq;
	u32 LocalFBKSeq;
	u32 RttSize;
	u32 RttCESize;	
	u16 flags;
    bool lossdetected;
};

struct rcv_data {
    u64 key; //key of a flow, {LOW16(srcip), LOW16(dstip), tcpsrc, tcpdst}
	u8 reorder;// identifying whether this flow is out-of-order
	u64 record_jiffies;
    u8 FEEDBACK;
	struct sw_flow_key *skey;
	struct datapath *dp ;
	struct sw_flow *flow;
	struct TreeNode *order_tree;

    u32 expected;
    struct ChannelInfo Channels[8];
    spinlock_t lock; //lock for read/write, write/write conflicts
    struct hlist_node hash;
    struct rcu_head rcu;
};

struct rcv_ack {
    u64 key;
    u32 rwnd;
	u32 rwnd_clamp;
	u32 snd_una;   //LastACK
	u32 snd_nxt;   //NextSeq
	u32 next_seq;
	u8 snd_wscale;
	u32 dupack_cnt;
	u32 MileStone;
	u8 Flags;
	u8 currentChannel;
    //for packet loss
    struct SeqChain *seq_chain;

	struct ChannelInfo Channels[8];
	spinlock_t lock;
	struct hlist_node hash;
    struct rcu_head rcu;
};


/*end of Yiran's structure*/
unsigned int ovs_net_id __read_mostly;

static struct genl_family dp_packet_genl_family;
static struct genl_family dp_flow_genl_family;
static struct genl_family dp_datapath_genl_family;

static const struct nla_policy flow_policy[];

static struct genl_multicast_group ovs_dp_flow_multicast_group = {
	.name = OVS_FLOW_MCGROUP
};

static struct genl_multicast_group ovs_dp_datapath_multicast_group = {
	.name = OVS_DATAPATH_MCGROUP
};

struct genl_multicast_group ovs_dp_vport_multicast_group = {
	.name = OVS_VPORT_MCGROUP
};

/*start of Yiran's function*/
static u16 ovs_hash_min(u64 key, int size) {
        u16 low16;
        u32 low32;

        low16 = key & ((1UL << 16) - 1);
        low32 = key & ((1UL << 32) - 1);

        low32 = low32 >> 16;
        return (low16 + low32) % (1 << size);
}

static void rcv_data_hashtbl_insert(u64 key, struct rcv_data *value)
{
        u32 bucket_hash;
        bucket_hash = ovs_hash_min(key, HASH_BITS(rcv_data_hashtbl)); //hash_min is the same as hash_long if key is 64bit
        //lock the table
        spin_lock(&datalock);
        hlist_add_head_rcu(&value->hash, &rcv_data_hashtbl[bucket_hash]);
        spin_unlock(&datalock);
}

static void free_rcv_ack_rcu(struct rcu_head *rp)
{
        struct rcv_ack * tofree = container_of(rp, struct rcv_ack, rcu);
        kfree(tofree);
}
static void free_rcv_data_rcu(struct rcu_head *rp)
{
        struct rcv_data * tofree = container_of(rp, struct rcv_data, rcu);
        kfree(tofree);
}

static void rcv_data_hashtbl_delete(struct rcv_data *value)
{
        //lock the table
        spin_lock(&datalock);
        hlist_del_init_rcu(&value->hash);
        spin_unlock(&datalock);
        call_rcu(&value->rcu, free_rcv_data_rcu);
}

//caller must use "rcu_read_lock()" to guard it
static struct rcv_data * rcv_data_hashtbl_lookup(u64 key)
{
        int j = 0;
        struct rcv_data * v_iter = NULL;


        j = ovs_hash_min(key, HASH_BITS(rcv_data_hashtbl));
        hlist_for_each_entry_rcu(v_iter, &rcv_data_hashtbl[j], hash)
            if (v_iter->key == key) 
                        return v_iter;
        return NULL; 
}

static void rcv_data_hashtbl_destroy(void)
{
        struct rcv_data * v_iter;
        struct hlist_node * tmp;
        int j = 0;

        rcu_barrier(); //wait until all rcu_call are finished

        spin_lock(&datalock); //no new insertion or deletion !
        hash_for_each_safe(rcv_data_hashtbl, j, tmp, v_iter, hash) {
                hash_del(&v_iter->hash);
                kfree(v_iter);
                pr_info("delete one entry from rcv_data_hashtbl table\n");
                printk("there is rest rcv_data_hashtbl entries not deleted.\n");
        }
        spin_unlock(&datalock);
}

/*functions for rcv_ack_hashtbl*/
//insert a new entru
static void rcv_ack_hashtbl_insert(u64 key, struct rcv_ack *value)
{
        u32 bucket_hash;
        bucket_hash = ovs_hash_min(key, HASH_BITS(rcv_ack_hashtbl)); //hash_min is the same as hash_long if key is 64bit
        //lock the table
        spin_lock(&acklock);
        hlist_add_head_rcu(&value->hash, &rcv_ack_hashtbl[bucket_hash]);
        spin_unlock(&acklock);
}



static void rcv_ack_hashtbl_delete(struct rcv_ack *value)
{
        //lock the table
        spin_lock(&acklock);
        hlist_del_init_rcu(&value->hash);
        spin_unlock(&acklock);
        call_rcu(&value->rcu, free_rcv_ack_rcu);
}

static struct rcv_ack * rcv_ack_hashtbl_lookup(u64 key)
{
        int j = 0;
        struct rcv_ack * v_iter = NULL;


        j = ovs_hash_min(key, HASH_BITS(rcv_ack_hashtbl));
        hlist_for_each_entry_rcu(v_iter, &rcv_ack_hashtbl[j], hash)
            if (v_iter->key == key) 
                        return v_iter;
        return NULL; 
}

//delete all entries in the hashtable
static void rcv_ack_hashtbl_destroy(void)
{
        struct rcv_ack * v_iter;
        struct hlist_node * tmp;
        int j = 0;

        rcu_barrier(); //wait until all rcu_call are finished

        spin_lock(&acklock); //no new insertion or deletion !
        hash_for_each_safe(rcv_ack_hashtbl, j, tmp, v_iter, hash) {
                hash_del(&v_iter->hash);
                kfree(v_iter);
                pr_info("delete one entry from rcv_ack_hashtbl table\n");
                printk("there is rest rcv_ack_hashtbl entries not deleted.\n");
        }
        spin_unlock(&acklock);
}

static void __hashtbl_exit(void) {
        rcv_data_hashtbl_destroy();
        rcv_ack_hashtbl_destroy();
}

static void SendOut(struct sk_buff* skb,struct rcv_data* entry)
{
	struct sw_flow_actions *sf_acts;
	struct sw_flow_key *key = entry->skey;
	struct sw_flow *flow = entry->flow;
	struct datapath *dp = entry->dp;
	
	sf_acts = rcu_dereference(flow->sf_acts);
	if (skb == NULL)	{
		//printk("here skb has been null.\n");
		return;
	}
	if (ovs_execute_actions(dp, skb, sf_acts, key) < 0) {
		printk("ovs_execute_actions failure!\n");
	}
	
}

void InOrder(struct TreeNode* root,struct rcv_data* entry)
{
    //printk("go to InOrder.\n");
    struct ListNode * head = NULL;
    if (root != NULL) {
        InOrder(root->left, entry);
        head = root->head;
        while (head != NULL)
        {
            //printk("going to sendout seq:%u, expected: %u\n", head->seq, entry->expected);
            SendOut(head->skb, entry);
            if (before(entry->expected, head->seq + head->tcp_data_len)) {
                entry->expected = head->seq + head->tcp_data_len;
                //printk("Inorder: update expected, %u.\n",entry->expected);
            }
            head = head->next;
        }
        InOrder(root->right, entry);
    }
}

void BufferDump(struct TreeNode* root,struct rcv_data* entry)
{
    struct ListNode * pkt = NULL;
    struct ListNode * ptmp = NULL;
    struct TreeNode * cur = root;
    struct TreeNode * ntmp = NULL;
    //printk("dump!\n");
    while (cur != NULL) {
        if (cur->left != NULL) { 
            cur = cur->left;
            //printk("find left\n");
            continue;
        }
        pkt = cur->head;
        while (pkt != NULL) { // dump pkts in the current node
            if (before(entry->expected, pkt->seq)) {
                //printk("expected:%u, actual:%u\n", entry->expected, pkt->seq);
                return;
            }
//            printk("send out: %u\n", pkt->seq);
            SendOut(pkt->skb, entry);
            entry->record_jiffies = jiffies;
            if (before(entry->expected, pkt->seq + pkt->tcp_data_len)) {
                entry->expected = pkt->seq + pkt->tcp_data_len;
            }
            ptmp = pkt->next;
            kfree(pkt);
            pkt = ptmp;
        }
        cur->head = NULL;
        cur->tail = NULL;
        if(cur->right != NULL) {
            ntmp = cur->right;
            cur->head = ntmp->head;
            cur->tail = ntmp->tail;
            cur->left = ntmp->left;
            cur->right = ntmp->right;
            if (cur->left != NULL) {
                cur->left->parent = cur;
            }
            if (cur->right != NULL) {
                cur->right->parent = cur;
            }
            kfree(ntmp);
            //printk("find right\n");
            continue;
        } else {
            if (cur->type == LEFT) {
                ntmp = cur->parent;
                if (ntmp->left != NULL) {
                    kfree(ntmp->left);
                    ntmp->left = NULL;
                    cur = ntmp;
                }
            } else if (cur->type == RIGHT) {
                ntmp = cur->parent;
                if (ntmp->right != NULL) {
                    kfree(ntmp->right);
                    ntmp->right = NULL;
                    cur = ntmp;
                }
            } else {
                break;
            }
        }
    }
}

void freeTree(struct TreeNode** root)
{
	struct ListNode* temp = NULL;
	if(*root == NULL)
	{
		return;
	}

	if ((*root)->left) {
		freeTree(&((*root)->left));
		(*root)->left = NULL;
	}
	if ((*root)->right) {
		freeTree(&((*root)->right));
		(*root)->right = NULL;
	}
	while((*root)->head)
	{
		temp = (*root)->head->next;
		kfree((*root)->head);
		(*root)->head = temp;
	}
	(*root)->head = NULL;
    (*root)->tail = NULL;
	kfree(*root);
	(*root) = NULL;
	
}
void insertToSeqList(struct rcv_ack* entry,u32 seq, u8 cid)
{
    struct SeqChain *q = NULL;
    struct SeqNode *l = NULL;

    
    //printk("Insert into seqList, seq: %u, cid:%u.\n",seq,cid);

    if(entry->seq_chain == NULL)
    {

        q = kzalloc(sizeof(struct SeqChain), GFP_ATOMIC);
        if(q!= NULL)
        {   
            l = kzalloc(sizeof(struct SeqNode), GFP_ATOMIC);
            if(l != NULL)
            {
                l->seq = seq;
                l->cid = cid;
                l->next = NULL;
                entry->seq_chain = q;
                entry->seq_chain->head = l;
                entry->seq_chain->tail = l; 
                
            }
            
        }
        
    }
    else
    {
        l = kzalloc(sizeof(struct SeqNode), GFP_ATOMIC);
        if(l != NULL)
        {
                
            l->seq = seq;
            l->cid = cid;
            l->next = NULL;
            entry->seq_chain -> tail ->next = l;
            entry->seq_chain -> tail = l;
        }
        
    }

    
}
u8 FindLossChannel(u32 seq, struct SeqChain *root)
{
    struct SeqNode * start;
    struct SeqNode * next;
    if(root == NULL)
    {
        return 8;
    }
    start = root->head;
    
    if(start == NULL)
    {
        return 8;
    }
    next = start ->next;
    if(next == NULL)
    {
        if(seq == start->seq || after(seq,start->seq))
        {
            return start->cid;
        }
        else
        {
            return 8;
        }
    }
    while(next!= NULL)
    {
        if(!before(seq, start->seq) && before(seq,next->seq))
        {
            return start->cid;
        }
        else if(after(start->seq,seq))
        {
            return 8;
        }
        else if(!before(seq,next->seq))
        {
            start = start->next;
            next = next->next;
        }
    }
    return start ->cid;
    
}



void freeChain(struct SeqChain *root, u32 ack, struct rcv_ack* entry)
{
    struct SeqNode * start;
    struct SeqNode * tmp;
    if(root == NULL)
    {
        //printk("enter into freeChain, but root is null.\n");
        return;
    }
    start = root->head;
    tmp = start;
    
    while(tmp != NULL && before(tmp->seq,ack))
    {
        
        if(entry->Channels[tmp->cid].lossdetected == true)
        {
            entry->Channels[tmp->cid].lossdetected = false;
        }
        //printk("free seqnode, seq: %u, ack:%u.\n",tmp->seq,ack);
        tmp = start->next;
        kfree(start);
        start = tmp;

    }
    start = NULL;
    root->head = tmp;
}

void insertToTree(struct TreeNode **root, struct sk_buff *skb, u32 seq, u32 tcp_data_len)
{
    // here the skb must be tcp
    u32 seqhead;
    u32 seqtail;
    u32 taillen;
    struct TreeNode *p = *root;
    struct TreeNode *q = NULL;
    struct TreeNode *parent = p;

    struct ListNode *l = kzalloc(sizeof(struct ListNode), GFP_ATOMIC);
    l->seq = seq;
    l->tcp_data_len = tcp_data_len;
    l->skb = skb;
    l->next = NULL;

    while (p != NULL) { // find node
        parent = p; 
        if (p->head == NULL) {
            p->head = l;
            p->tail = l;
            return;
        }
        seqhead = p->head->seq;
        seqtail = p->tail->seq;
        taillen = p->tail->tcp_data_len;
        if (before(seq, seqhead)) {
            p = p->left;
            //printk("go left %u by %u\n", seq, seqhead);
        } else if (!after(seq, seqtail + taillen)) { // get node
            p->tail->next = l;
            p->tail = l;
            p->tail->next = NULL;
            //printk("append %u by %u\n", seq, seqtail + taillen);
            return;
        } else {
            p = p->right;
            //printk("go right %u by %u\n", seq, seqtail + taillen);
        }
    }

    q = kzalloc(sizeof(struct TreeNode), GFP_ATOMIC);
    q->left = q->right = NULL; 
    q->head = l;
    q->tail = l;   

    if (*root == NULL) { // if the root is NULL
        q->parent = NULL;
        q->type = NONE;
        *root = q; 
    } else if (before(seq, parent->head->seq)) { // if the node is the left child of parent
        parent->left = q;   
        q->parent = parent;
        q->type = LEFT;
        //printk("add left %u \n", seq);
    } else { // if the node is the right child of parent
        parent->right = q;  
        q->parent = parent;
        q->type = RIGHT;
        //printk("add right %u \n", seq);
    }
}

void addToBuffer(struct sw_flow_key *key,struct sk_buff *skb,struct sw_flow *flow,struct datapath *dp,struct rcv_data * the_entry)
{
    struct iphdr *nh;
    struct tcphdr * tcp;
    struct TreeNode * q = NULL;
    struct ListNode* l = NULL;
    u32 tcp_data_len;
    u32 seq;
    nh = ip_hdr(skb);
    tcp = tcp_hdr(skb);
    seq = ntohl(tcp->seq);
    tcp_data_len = ntohs(nh->tot_len) - (nh->ihl << 2) - (tcp->doff << 2);
    // record the time of the first skb come into the buffer 
    if (the_entry->order_tree == NULL) {
        l = kzalloc(sizeof(struct ListNode), GFP_ATOMIC);
        q = kzalloc(sizeof(struct TreeNode), GFP_ATOMIC);
        if(l == NULL || q == NULL) {
            printk("kzalloc(sizeof(struct ListNode),GFP_ATOMIC) fail!\n");
            return ;
        }
        l->seq = seq;
        l->tcp_data_len = tcp_data_len;
        l->skb = skb;
        l->next = NULL;
        q->left = q->right = NULL ; 
        q->parent = NULL;
        q->type = NONE;
        q->head = l;
        q->tail = l;   
        the_entry->order_tree = q;
        the_entry->record_jiffies = jiffies;
    } else {
        insertToTree(&(the_entry->order_tree), skb, seq, tcp_data_len);
    }
    /*
       if(after(seq + tcp_data_len, the_entry->maxseq))	{
       the_entry->maxseq = seq + tcp_data_len;
       }
     */
    the_entry->skey = key;
    the_entry->flow = flow;
    the_entry->dp = dp;
}

void checkBuffer(unsigned long p)
{
    int j = 0;
    u64 now = jiffies;
    struct rcv_data * v_iter = NULL;
    spin_lock(&datalock);   
    for(j = 0; j < (1 << TBL_SIZE); j++)
    {
        hlist_for_each_entry_rcu(v_iter, &rcv_data_hashtbl[j], hash) {
            if (now - v_iter->record_jiffies >= usecs_to_jiffies(400)) {
                spin_lock(&v_iter->lock);
                if(v_iter->order_tree != NULL)
                {
                    //printk("check buffer!\n");
                    InOrder(v_iter->order_tree, v_iter);
                    freeTree(&(v_iter->order_tree));
                    v_iter->order_tree = NULL;
                }
                v_iter->reorder = 0;
                spin_unlock(&v_iter->lock);
            }
		}
	}    
	spin_unlock(&datalock); 	
	my_timer.expires = jiffies + usecs_to_jiffies(25);
	add_timer(&my_timer); 
}

static u64 get_tcp_key64(u32 ip1, u32 ip2, u16 tp1, u16 tp2) {
	u64 key = 0;
	u64 part1, part2, part3, part4;

	part1 = ip1 & ((1<<16) - 1);// get the lower 16 bits of u32
	part1 = part1 << 48; //the highest 16 bits of the result

	part2 = ip2 & ((1<<16) - 1);	 
	part2 = part2 << 32;	

	part3 = tp1 << 16;

	part4 = tp2;

	key = part1 + part2 + part3 + part4;
	return key;

}
/*helper function, determine the direction of the traffic (packet), i.e., go to the net or come to the host? */
static bool ovs_packet_to_net(struct sk_buff *skb) {
        if (strncmp(skb->dev->name, BRIDGE_NAME, 2) == 0)
                return 1;
        else
                return 0;
}

static u8 ovs_tcp_parse_options(const struct sk_buff *skb) {
        u8 snd_wscale = 0;

        const unsigned char *ptr;
        const struct tcphdr *th = tcp_hdr(skb);
        int length = (th->doff * 4) - sizeof(struct tcphdr);

        ptr = (const unsigned char *)(th + 1);

        while (length > 0) {
                int opcode = *ptr++;
                int opsize;
                switch (opcode) {
                case TCPOPT_EOL:
                        return 0;
                case TCPOPT_NOP:        /* Ref: RFC 793 section 3.1 */
                        length--;
                        continue;
                default:
						opsize = *ptr++;
                        if (opsize < 2) /* "silly options" */
                                return 0;
                        if (opsize > length)
                                return 0; /* don't parse partial options */
                        switch (opcode) {
                        case TCPOPT_WINDOW:
                                if (opsize == TCPOLEN_WINDOW && th->syn) {
                                        snd_wscale = *(__u8 *)ptr;
                                        if (snd_wscale > 14) {
                                                printk("Illegal window scaling: %u\n", snd_wscale);
                                                snd_wscale = 14;
                                        }
                                }
                                break;
                        default:
                                break;
                        }
                        ptr += opsize-2;
                        length -= opsize;
                }
        }
        return snd_wscale;
}

static int ovs_pack_FBK_info(struct sk_buff * skb, u32 ReceivedCount, u32 fbkNumber ,u16 RCE,u16 fbkid) {
	struct iphdr *nh;
    struct tcphdr * tcp;
	u16 header_len;
	u16 old_total_len;
	u16 old_tcp_len;
	u16 fbk_rce_rcv = 0;
	
	//add TCP option
	u8 kind = 15;
	u8 len  = 8;
	u8 FBK_INFO_LEN = 8;
	u32 cmp = (1 << 20) - 1;
	
	/*the caller makes sure this is a TCP packet*/
	nh = ip_hdr(skb);
	tcp = tcp_hdr(skb);


	//printk("enter into ovs_pack_FBK_info:outgoing ack:%u   seq:%u.  \n",ntohl(tcp->ack_seq),ntohl(tcp->seq));
	header_len = skb->mac_len + (nh->ihl << 2) + 20;
	old_total_len = ntohs(nh->tot_len); 
	old_tcp_len = tcp->doff << 2;
	
	if (skb_cow_head(skb, FBK_INFO_LEN) < 0)
	{
		printk("skb_cow_head(skb, FBK_INFO_LEN) < 0:outgoing ack:%u.\n",ntohl(tcp->ack_seq));
		return -ENOMEM;
	}
		

	//printk("we are packing FBK: fbkNumber:%u,fbkcid:%u, isRCE:%u, receivedCount:%u\n",fbkNumber,fbkid,RCE,ReceivedCount);
	
	fbk_rce_rcv += (fbkid << 13);
	fbk_rce_rcv += (RCE << 12);
	if(ReceivedCount > cmp)
	{
		ReceivedCount = cmp;
	}
	ReceivedCount = ReceivedCount >> 8;
	fbk_rce_rcv += ReceivedCount;
	/*printk("before maring pack, tcp->doff:%u, nh->ip_hdr:%u, tcp->res1:%u,skb->len:%u, \
		skb->data_len:%u,skb->mac_len:%u,skb->csum:%u,skb->local_df:%u,skb->cloned:%u, \
		skb->nohdr:%u,skb->nfctinfo:%u,skb->pkt_type:%u,skb->fclone:%u,skb->ipvs_property:%u, \
		skb->truesize:%u,skb->ip_summed:%u,skb->data:%u,skb->head:%u,skb->tail:%u,skb->end:%u, \
		skb->csum_start:%u,skb->csum_offset:%u,skb->transport_header:%u,tcp->hdr_len:%u\n",
		ntohs(tcp->doff), ntohs(nh->tot_len), tcp->res1,skb->len,
		skb->data_len,skb->mac_len,skb->csum,skb->local_df,skb->cloned,
		skb->nohdr,skb->nfctinfo,skb->pkt_type,skb->fclone,skb->ipvs_property,
		skb->truesize,skb->ip_summed,skb->data,skb->head,skb->tail,skb->end,
		skb->csum_start,skb->csum_offset,skb->transport_header, tcp_hdrlen(skb));*/

	if(skb->end - skb->tail < 8)
	{
		printk("not enough room:outgoing ack:%u.\n",ntohl(tcp->ack_seq));
		return -ENOMEM;
	}
	else
	{
		//printk("enough room to add option.\n");
	}
	//payload = skb->tail - (skb->mac_header + header_len);
	skb_push(skb, FBK_INFO_LEN);
	//skb_put(skb, FBK_INFO_LEN);
	memmove(skb_mac_header(skb) - FBK_INFO_LEN, skb_mac_header(skb), header_len);
	//memmove(skb_mac_header(skb) + header_len + FBK_INFO_LEN,skb_mac_header(skb) + header_len, payload);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, skb->mac_len);
	skb_set_transport_header(skb, skb->mac_len + (ip_hdr(skb)->ihl << 2));

	fbk_rce_rcv = htons(fbk_rce_rcv);
	fbkNumber = htonl(fbkNumber);
	
	memcpy(skb_mac_header(skb) + header_len , &kind, 1);
	memcpy(skb_mac_header(skb) + header_len + 1, &len, 1);
	
	memcpy(skb_mac_header(skb) + header_len + 2, &fbk_rce_rcv, 2);
	memcpy(skb_mac_header(skb) + header_len + 4, &fbkNumber, 4);

	
	/*we believe that the NIC will re-calculate checksums for us*/
	nh = ip_hdr(skb);
	tcp = tcp_hdr(skb);
    //add by yiran: when not support offload
    //csum_replace2(&nh->check, nh->tot_len, htons(old_total_len + FBK_INFO_LEN));


	nh->tot_len = htons(old_total_len + FBK_INFO_LEN);
    //add by yiran: when not support offload

    //csum_replace2(&tcp->check, htons(tcp->doff << 12), htons(((old_tcp_len + FBK_INFO_LEN) >> 2) << 12));


	tcp->doff = ((old_tcp_len + FBK_INFO_LEN) >> 2);
    //printk("before pack:tcp->check:%02x ,ack:%u   seq:%u.  \n",ntohs(tcp->check),ntohl(tcp->ack_seq),ntohl(tcp->seq));

	//csum_replace2(&tcp->check, htons(tcp->cwr << 15), htons(1 << 15));

    //set FBK = 1 

    tcp->cwr = 1;
    //when offload checksum
	skb->csum_start = skb->csum_start - 8;
	tcp->check = ~tcp_v4_check(skb->len - header_len + 20, nh->saddr, nh->daddr, 0);
	ip_send_check(nh);
	/*printk("after maring pack, tcp->doff:%u, nh->ip_hdr:%u, tcp->res1:%u,skb->len:%u, \
		skb->data_len:%u,skb->mac_len:%u,skb->csum:%u,skb->local_df:%u,skb->cloned:%u, \
		skb->nohdr:%u,skb->nfctinfo:%u,skb->pkt_type:%u,skb->fclone:%u,skb->ipvs_property:%u, \
		skb->truesize:%u,skb->ip_summed:%u,skb->data:%u,skb->head:%u,skb->tail:%u,skb->end:%u, \
		skb->csum_start:%u,skb->csum_offset:%u,skb->transport_header:%u,tcp->hdr_len:%u\n",
		ntohs(tcp->doff), ntohs(nh->tot_len), tcp->res1,skb->len,
		skb->data_len,skb->mac_len,skb->csum,skb->local_df,skb->cloned,
		skb->nohdr,skb->nfctinfo,skb->pkt_type,skb->fclone,skb->ipvs_property,
		skb->truesize,skb->ip_summed,skb->data,skb->head,skb->tail,skb->end,
		skb->csum_start,skb->csum_offset,skb->transport_header, tcp_hdrlen(skb));*/
	//printk("end of ovs_pack_FBK_info:outgoing ack:%u.\n",ntohl(tcp->ack_seq));
    //when not offload checksum
    /*header_len = (ntohs(nh->tot_len) - (nh->ihl << 2));
    tcp->check = 0;
    tcp->check = tcp_v4_check(header_len,nh->saddr,nh->daddr,csum_partial((char*) tcp, header_len, 0));
    ip_send_check(nh);*/
    //printk("after pack:tcp->check:%02x ,ack:%u   seq:%u.  \n",ntohs(tcp->check),ntohl(tcp->ack_seq),ntohl(tcp->seq));
    //csum_replace2(&nh->check, htons(old_total_len), nh->tot_len);



	return 0; 
}

static int ovs_unpack_FBK_info(struct sk_buff* skb, u32 * fbkNumber, u32 * receivedCount,u8 * isRCE,u8 * fbkcid) {
	struct iphdr *nh;
    struct tcphdr * tcp;
    u16 *fbkRCERece;
    u16 header_len;
	u16 temp1;
	u16 old_total_len;
	u16 old_tcp_len;
	u16 payload;
	u16 newlen;
	int err;

	u8 ECN_INFO_LEN = 8;
        /*the caller makes sure this is a TCP packet*/
    nh = ip_hdr(skb);
    tcp = tcp_hdr(skb);

	header_len = skb->mac_len + (nh->ihl << 2) + 20;
	old_total_len = ntohs(nh->tot_len);
	old_tcp_len = tcp->doff << 2;


	err = skb_ensure_writable(skb, header_len);
	if (unlikely(err))
		return err;

	memset(receivedCount, 0, sizeof(*fbkRCERece));
	memset(fbkNumber, 0, sizeof(*fbkNumber));

	payload = skb->tail - (skb->mac_header + header_len);
	
	memcpy(&temp1, skb_mac_header(skb) + header_len + 2, 2);
    	memcpy(fbkNumber, skb_mac_header(skb) + header_len + 4, 4);

    	temp1 = ntohs(temp1);
	
	*fbkcid = (temp1 >> 13);
	*isRCE = (temp1 >> 12) & 1;
	*receivedCount = (temp1 & ((1 << 12) - 1)) << 8;
	
	//printk("we are unpack FBK: fbkNumber:%u,fbkcid:%u, isRCE:%u, receivedCount:%u\n",*fbkNumber,*fbkcid,*isRCE,*receivedCount);

	skb_postpull_rcsum(skb, skb_mac_header(skb) + header_len, ECN_INFO_LEN);

	//printk("we are unpack (before), tcp->src:%u, tcp->dst:%u, tcp->seq:%u, tcp->ack_seq:%u, tcp->res1:%u, nh->tot_len:%u, tcp->doff:%u, \n fbkNumber:%u, recevicedCount:%u, fbkid:%d, isRCE:%d, skb->ip_summed:%u, skb_csum:%u\n",ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq), tcp->res1, ntohs(nh->tot_len), tcp->doff, *fbkNumber, *receivedCount, *fbkcid, *isRCE,skb->ip_summed, skb->csum);
	//memmove(skb_mac_header(skb) + ECN_INFO_LEN, skb_mac_header(skb), header_len);
	memmove(skb_mac_header(skb) + header_len, skb_mac_header(skb) + header_len + ECN_INFO_LEN, payload - ECN_INFO_LEN);
	//__skb_pull(skb, ECN_INFO_LEN);
	newlen = skb->len - 8;
    //printk(KERN_INFO "enter into : skb_trim\n");
	__skb_trim(skb,newlen);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, skb->mac_len);
    	skb_set_transport_header(skb, skb->mac_len + (ip_hdr(skb)->ihl << 2));

	nh = ip_hdr(skb);
	tcp = tcp_hdr(skb);
	
	nh->tot_len = htons(old_total_len - ECN_INFO_LEN);
    //when offload checksum
	csum_replace2(&nh->check, htons(old_total_len), nh->tot_len);

    //csum_replace2(&tcp->check, htons(tcp->doff << 12), htons(((old_tcp_len - ECN_INFO_LEN) >> 2) << 12));


    tcp->doff = ((old_tcp_len - ECN_INFO_LEN) >> 2);
    //printk("before unpack:tcp->check:%02x ,ack:%u   seq:%u.  \n",ntohs(tcp->check),ntohl(tcp->ack_seq),ntohl(tcp->seq));


    //when not offload checksum
    /*header_len = (ntohs(nh->tot_len) - (nh->ihl << 2));
    tcp->check = 0;
    tcp->check = tcp_v4_check(header_len,nh->saddr,nh->daddr,csum_partial((char*) tcp, header_len, 0));*/
    //printk("after unpack:tcp->check:%02x ,ack:%u   seq:%u.  \n",ntohs(tcp->check),ntohl(tcp->ack_seq),ntohl(tcp->seq));

	
	//printk("we are here unpack (after), tcp->src:%u, tcp->dst:%u, tcp->seq:%u, tcp->ack_seq:%u, tcp->res1:%u, nh->tot_len:%u, tcp->doff:%u, \n fbkNumber:%u, recevicedCount:%u, fbkid:%d, isRCE:%d, skb->ip_summed:%u, skb_csum:%u\n",ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq), tcp->res1, ntohs(nh->tot_len), tcp->doff, *fbkNumber, *receivedCount, *fbkcid, *isRCE,skb->ip_summed, skb->csum);
	
	return 0;	
}

u16 getTrueSrcPort(struct tcphdr * tcp)
{
	u16 curPort = ntohs(tcp->source);
	u16 port;
	u8 curChannel = tcp->res1 >> 1;
	//port = ((curPort + curChannel) & 7) + ((curPort & (~ 7)));
    port = curPort - curChannel;
	//printk("curChannel:%u\n",curChannel);
	//printk("Get the true srcport: %u, destport:%u,\n",port,ntohs(tcp->dest));
	return port;
}

int Window_based_Channel_Choosing(struct rcv_ack* the_entry, u16 psize){
    int c = the_entry->currentChannel;
    int check = c;
    u16 r1,r2;
    u32 onfly1,onfly2,rwnd1,rwnd2,rwnd;
    u32 avail = 0;
    u32 avail1 = 0;
    u32 avail2 = 0;
    struct ChannelInfo *ch = NULL;
    u8 i = 0;
    u32 max = 0;
    int maxC = (c + 1) & 7;
    u32 onfly = 0;
    u64 tmp = 0x100000000;
    
    //after packet loss, avoid the loss channel, if no loss channel, degrade to one channel
    //maxC = (c + 1) & 7;
    //the_entry->Channels[maxC].LocalSendSeq += psize;
    //the_entry->currentChannel = maxC;
    //return maxC;
    if(the_entry->Flags & VMS_SIN_FLAG)
    {        
        for (i = 0; i <= VMS_CHANNEL_NUM - 1; i++)  {
            
            ch = &(the_entry -> Channels[i]);
            if(ch->lossdetected == true)
            {
                continue;
            }               
            tmp += ch->LocalSendSeq - ch->LocalFBKSeq;
            onfly = (u32)tmp;               
            if (max <= ch->rwnd - onfly) {
                        max = ch->rwnd - onfly;
                        maxC = i;
            }  
        }
        the_entry->Channels[maxC].LocalSendSeq += psize;
        the_entry->currentChannel = maxC;
        return maxC;        
        
    }
    max = 0;
    maxC = (c + 1) & 7;
    /*get_random_bytes(&r1, sizeof(r1));
    get_random_bytes(&r2, sizeof(r2));
    r1 = r1 % 8;
    if(r1 < 0)
    {
        r1 = 0;
    }
    r2 = r2 % 8;
    if(r2 < 0)
    {
        r2 = 0;
    }*/
    for (i = 1; i <= VMS_CHANNEL_NUM; i++)	{
        ch = &(the_entry -> Channels[c]);
        if (ch == NULL) {
            printk("error get corresponding channel when choose channel\n");
            return -1;
        }
        tmp += ch->LocalSendSeq - ch->LocalFBKSeq;
        onfly = (u32)tmp;
        if (onfly + psize <= ch->rwnd) {
            the_entry->Channels[c].LocalSendSeq += psize;
            the_entry->currentChannel = c; 
            //printk("find avaliable channel: %u, onfly: %u, psize: %u, ch->rwnd: %u.\n",c, onfly,psize,ch->rwnd);
            return c;
        } else {
            //printk("find larger channel: %u, onfly: %u, psize: %u, ch->rwnd: %u.\n",c, onfly,psize,ch->rwnd);
            if (max <= ch->rwnd - onfly) {
                max = ch->rwnd - onfly;
                maxC = c;
            }
        }
        c = (c + 1) & 7;
    }
    //Yiran: if all channel has the same window, and all window size is not enough, we have to make sure not to always choose the same channel.
    //this is useful at the beginning. all ch->rwnd: 2800
    if(maxC == check)
    {
        maxC = (maxC + 1) & 7;
    }
    the_entry->Channels[maxC].LocalSendSeq += psize;
    the_entry->currentChannel = maxC;
    return maxC;
    /*ch = &(the_entry -> Channels[r1]);
    onfly1 = ch->LocalSendSeq - ch->LocalFBKSeq;
    rwnd1 = ch->rwnd;
    if(rwnd1 > onfly1)
    {
        avail1 = rwnd1 - onfly1;
    }
    
    ch = &(the_entry -> Channels[r2]);
    onfly2 = ch->LocalSendSeq - ch->LocalFBKSeq;
    rwnd2 = ch->rwnd;
    if(rwnd2 > onfly2)
    {
        avail2 = rwnd2 - onfly2;
    }


    ch = &(the_entry -> Channels[c]);
    onfly = ch->LocalSendSeq - ch->LocalFBKSeq;
    rwnd = ch->rwnd;
    if(rwnd > onfly)
    {
        avail = rwnd - onfly;
    }


    if(avail1 > avail2)
    {
        if(avail1 > avail)
        {
            the_entry->Channels[r1].LocalSendSeq += psize;
            the_entry->currentChannel = r1;
            return r1;
        }
        else
        {
            the_entry->Channels[c].LocalSendSeq += psize;
            the_entry->currentChannel = c;
            return c;
        }
    }
    else
    {
        if(avail2 > avail)
        {
            the_entry->Channels[r2].LocalSendSeq += psize;
            the_entry->currentChannel = r2;
            return r2;
        }
        else
        {
            the_entry->Channels[c].LocalSendSeq += psize;
            the_entry->currentChannel = c;
            return c;
        }
    }

    

    return c;*/
}

int OnFeedBack(struct rcv_ack* the_entry,int fbkid,u32 receiveCount,u32 fbkNumber,int isRCE,u32 seq_ack)
{
    struct ChannelInfo *ch = NULL;
    u64 adder = 0;
    u64 sum = 0;
    int i = 0;
    ch = &(the_entry->Channels[fbkid]);

    if(ch == NULL)
    {
        printk("Error to get the corresponding channel in OnFeedBack()\n");
        return 1;
    }
    if (receiveCount > 0) {
        //printk("receiveCount:%u:%u\n",receiveCount, fbkid);
        ch->LocalFBKSeq = fbkNumber;
        ch->RttSize += receiveCount;
        if(isRCE == 0) {
            if(ch->rwnd < ch->rwnd_ssthresh) {
                adder = receiveCount >> 1;
            } else {
                if(the_entry->Flags & VMS_SIN_FLAG) {
                    adder = ((MSS * receiveCount) >> 1) / ch->rwnd; 
                } else {
                    adder = ((MSS * receiveCount) >> 1 >> 3) / ch->rwnd; 
                }
            }
            if (adder < 1) {
                adder = 1;
            }
            ch->rwnd += adder;
            if (ch->rwnd > 20000000) {
                ch->rwnd = 20000000;
            }
            the_entry->rwnd += adder;
        } else {
            //printk("RCE==1!.fbkid:%u.\n",fbkid);
            ch->RttCESize += receiveCount;
            ch->rwnd_ssthresh = ch->rwnd >> 1;
            if (ch->rwnd_ssthresh < 2800)
            {
                ch->rwnd_ssthresh = 2800;
            }
        }
    }

    if(before(the_entry->MileStone,seq_ack)||the_entry->MileStone==seq_ack)
    {
        sum = 0;
        for(i = 0;i< VMS_CHANNEL_NUM ;i++)
        {
            ch = &(the_entry->Channels[i]);
            // alpha = (1 - g) * alpha + g * F 
            if(ch->RttCESize > 0 && ch->RttSize > 0)
            {
                ch->alpha = ch->alpha - (ch->alpha >> dctcp_shift_g) + (ch->RttCESize << (10U - dctcp_shift_g)) / ch->RttSize;
                ch->rwnd = max(ch->rwnd - ((ch->rwnd * ch->alpha) >> 11U), RWND_MIN);
            } else {
                ch->alpha = ch->alpha - (ch->alpha >> dctcp_shift_g);
            }

            ch->RttCESize = 0;
            ch->RttSize = 0;	
            sum += ch->rwnd;
            //printk("%u: ch->rwnd:%u; ch->alpha:%u.\n", i, ch->rwnd, ch->alpha);
        }
        the_entry->rwnd = sum;
        //("sum:%u.\n",sum);
        the_entry->MileStone = the_entry->snd_nxt + 1;
    }
    return 0;
}




/*end of Yiran's function*/


/* Check if need to build a reply message.
 * OVS userspace sets the NLM_F_ECHO flag if it needs the reply.
 */
static bool ovs_must_notify(struct genl_family *family, struct genl_info *info,
			    unsigned int group)
{
	return info->nlhdr->nlmsg_flags & NLM_F_ECHO ||
	       genl_has_listeners(family, genl_info_net(info), group);
}

static void ovs_notify(struct genl_family *family, struct genl_multicast_group *grp,
		       struct sk_buff *skb, struct genl_info *info)
{
	genl_notify(family, skb, info, GROUP_ID(grp), GFP_KERNEL);
}

/**
 * DOC: Locking:
 *
 * All writes e.g. Writes to device state (add/remove datapath, port, set
 * operations on vports, etc.), Writes to other state (flow table
 * modifications, set miscellaneous datapath parameters, etc.) are protected
 * by ovs_lock.
 *
 * Reads are protected by RCU.
 *
 * There are a few special cases (mostly stats) that have their own
 * synchronization but they nest under all of above and don't interact with
 * each other.
 *
 * The RTNL lock nests inside ovs_mutex.
 */

static DEFINE_MUTEX(ovs_mutex);

void ovs_lock(void)
{
	mutex_lock(&ovs_mutex);
}

void ovs_unlock(void)
{
	mutex_unlock(&ovs_mutex);
}

#ifdef CONFIG_LOCKDEP
int lockdep_ovsl_is_held(void)
{
	if (debug_locks)
		return lockdep_is_held(&ovs_mutex);
	else
		return 1;
}
#endif

static int queue_gso_packets(struct datapath *dp, struct sk_buff *,
			     const struct sw_flow_key *,
			     const struct dp_upcall_info *,
			     uint32_t cutlen);
static int queue_userspace_packet(struct datapath *dp, struct sk_buff *,
				  const struct sw_flow_key *,
				  const struct dp_upcall_info *,
				  uint32_t cutlen);

/* Must be called with rcu_read_lock. */
static struct datapath *get_dp_rcu(struct net *net, int dp_ifindex)
{
	struct net_device *dev = dev_get_by_index_rcu(net, dp_ifindex);

	if (dev) {
		struct vport *vport = ovs_internal_dev_get_vport(dev);
		if (vport)
			return vport->dp;
	}

	return NULL;
}

/* The caller must hold either ovs_mutex or rcu_read_lock to keep the
 * returned dp pointer valid.
 */
static inline struct datapath *get_dp(struct net *net, int dp_ifindex)
{
	struct datapath *dp;

	WARN_ON_ONCE(!rcu_read_lock_held() && !lockdep_ovsl_is_held());
	rcu_read_lock();
	dp = get_dp_rcu(net, dp_ifindex);
	rcu_read_unlock();

	return dp;
}

/* Must be called with rcu_read_lock or ovs_mutex. */
const char *ovs_dp_name(const struct datapath *dp)
{
	struct vport *vport = ovs_vport_ovsl_rcu(dp, OVSP_LOCAL);
	return ovs_vport_name(vport);
}

static int get_dpifindex(const struct datapath *dp)
{
	struct vport *local;
	int ifindex;

	rcu_read_lock();

	local = ovs_vport_rcu(dp, OVSP_LOCAL);
	if (local)
		ifindex = local->dev->ifindex;
	else
		ifindex = 0;

	rcu_read_unlock();

	return ifindex;
}

static void destroy_dp_rcu(struct rcu_head *rcu)
{
	struct datapath *dp = container_of(rcu, struct datapath, rcu);

	ovs_flow_tbl_destroy(&dp->table);
	free_percpu(dp->stats_percpu);
	kfree(dp->ports);
	kfree(dp);
}

static struct hlist_head *vport_hash_bucket(const struct datapath *dp,
					    u16 port_no)
{
	return &dp->ports[port_no & (DP_VPORT_HASH_BUCKETS - 1)];
}

/* Called with ovs_mutex or RCU read lock. */
struct vport *ovs_lookup_vport(const struct datapath *dp, u16 port_no)
{
	struct vport *vport;
	struct hlist_head *head;

	head = vport_hash_bucket(dp, port_no);
	hlist_for_each_entry_rcu(vport, head, dp_hash_node) {
		if (vport->port_no == port_no)
			return vport;
	}
	return NULL;
}

/* Called with ovs_mutex. */
static struct vport *new_vport(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = ovs_vport_add(parms);
	if (!IS_ERR(vport)) {
		struct datapath *dp = parms->dp;
		struct hlist_head *head = vport_hash_bucket(dp, vport->port_no);

		hlist_add_head_rcu(&vport->dp_hash_node, head);
	}
	return vport;
}

void ovs_dp_detach_port(struct vport *p)
{
	ASSERT_OVSL();

	/* First drop references to device. */
	hlist_del_rcu(&p->dp_hash_node);

	/* Then destroy it. */
	ovs_vport_del(p);
}

/* Must be called with rcu_read_lock. */
void ovs_dp_process_packet(struct sk_buff *skb, struct sw_flow_key *key)
{
	int reorder = 0;
    //u32 expected = 0;
    //u16 header_len;
    //u16 old,new;
    u16 cCh = 8;
    int index;
    struct rcv_data * tmp_entry = NULL;
	const struct vport *p = OVS_CB(skb)->input_vport;
	struct datapath *dp = p->dp;
	struct sw_flow *flow;
	struct sw_flow_actions *sf_acts;
	struct dp_stats_percpu *stats;
	u64 *stats_counter;
	u32 n_mask_hit;
	struct iphdr *nh;
    struct tcphdr * tcp;

	stats = this_cpu_ptr(dp->stats_percpu);

    if(ntohs(skb->protocol) == ETH_P_IP) {//this is an IP packet
        nh = ip_hdr(skb);
        if(nh->protocol == IPPROTO_TCP) {//this is an TCP packet
            tcp = tcp_hdr(skb);
			reorder = 0;
            // Yiran: outgoing to the NIC, the first syn packet, enable VMS
            if (tcp->syn && ovs_packet_to_net(skb)) {
                //printk(KERN_INFO "outgoing syn. seq:%u.\n",ntohl(tcp->seq));
                //printk(KERN_INFO "outgoing syn before: checksum:%02x.\n",ntohs(tcp->check));
                /*csum_replace2(&tcp->check, htons(tcp->res1 << 12), htons((tcp->res1 | OVS_VMS_ENABLE) << 12));*/
                tcp->res1 |= OVS_VMS_ENABLE;
                //printk(KERN_INFO "outgoing syn after: checksum:%02x.\n",ntohs(tcp->check));
                //Yiran: if not support ECN, enable ECN. get the last two bits			
                if ((nh->tos & OVS_ECN_MASK) == OVS_ECN_ZERO) {
                    ipv4_change_dsfield(nh, 0, OVS_ECN_ONE);					
                }

            }
			
			if(likely(tcp->res1 & OVS_VMS_ENABLE))
			{
                //Yiran: start the timer for reorder buffer
				if(is_init == false)
				{
                    
					is_init =true;
					init_timer(&my_timer);
					my_timer.function = checkBuffer;
					my_timer.data = 0;
					my_timer.expires = jiffies + usecs_to_jiffies(1);
					//printk("The timer set up!\n");
					//add_timer(&my_timer);
				}
			}	
        }//it was an TCP packet
    }//it was an IP packet

	if(ntohs(skb->protocol) == ETH_P_IP) {//this is an IP packet
          nh = ip_hdr(skb);
          if(nh->protocol == IPPROTO_TCP) {//this is an TCP packet
			u32 srcip;
			u32 dstip;
			u16 srcport;
			u16 dstport;
			u64 tcp_key64;            
			tcp = tcp_hdr(skb);
			srcip = ntohl(nh->saddr);
			dstip = ntohl(nh->daddr);
			/*Yiran's logic:
			  For sVMS,the srcport is the true srcport;
			  For rVMS,the srcport is not the true srcport;
			*/
			srcport = ntohs(tcp->source);
			dstport = ntohs(tcp->dest);	
			//outgoing SYN or SYN/ACK or FIN, insert/delete entry in rcv_ack_hashtbl
			if (ovs_packet_to_net(skb)) {
			    //Yiran's logic: here is the original srcport
				if (unlikely(tcp->syn)) {//insert an entry to rcv_ack_hashtbl
					struct rcv_ack * new_entry = NULL;
					//Yiran: pay attention to the parameter order !!!!!!!!!!
					tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);
					rcu_read_lock();
					new_entry = rcv_ack_hashtbl_lookup(tcp_key64);
					rcu_read_unlock();
					if (likely(!new_entry)) {
						new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
						new_entry->key = tcp_key64;
						rcv_ack_hashtbl_insert(tcp_key64, new_entry);
                        //printk("Outgoing SYN, insert in rcv_ack_hashbtl, src %u-->dest %u.\n",srcport,dstport);    						
					}	
					new_entry->rwnd = RWND_INIT;
					new_entry->rwnd_clamp = RWND_CLAMP;
					new_entry->snd_una = ntohl(tcp->seq);      //LastACK
					new_entry->snd_nxt = ntohl(tcp->seq) + 1;  //SYN takes 1 byte
					new_entry->next_seq = new_entry->snd_nxt;
					new_entry->MileStone = new_entry->next_seq + 1;
					for(index = 0 ; index < VMS_CHANNEL_NUM ; index ++)
					{
						new_entry->Channels[index].RttSize = 0;
						new_entry->Channels[index].RttCESize = 0;
						new_entry->Channels[index].LocalSendSeq = 0;
						new_entry->Channels[index].LocalFBKSeq = 0;
						new_entry->Channels[index].LocalRecvSeq = 0;
						new_entry->Channels[index].receivedCount = 0;
						new_entry->Channels[index].rwnd = RWND_INIT;
						new_entry->Channels[index].rwnd_ssthresh = RWND_SSTHRESH_INIT;//infinite
						new_entry->Channels[index].alpha = DCTCP_ALPHA_INIT;
						new_entry->Channels[index].flags = 0;
                       
                        new_entry->Channels[index].lossdetected = false;
					}
					new_entry->currentChannel = 0;
					new_entry->dupack_cnt = 0;
					new_entry->Flags = 0;
                    new_entry->seq_chain = NULL;
					spin_lock_init(&new_entry->lock);							
				}
				/*TODO: we may also need to consider RST */
				if (unlikely(tcp->fin || tcp->rst)) {
					struct rcv_ack * new_entry = NULL;
					//pay attention to the parameter order
                    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);
					rcu_read_lock();
                    new_entry = rcv_ack_hashtbl_lookup(tcp_key64);
					rcu_read_unlock();
					if (likely(new_entry)) {
						rcv_ack_hashtbl_delete(new_entry);
                        //printk(KERN_INFO "rcv_ack_hashtbl new entry deleted. %d --> %d.\n",srcport, dstport);	
					}
						
				}
				
			}//it was outgoing SYN/FIN
			else { 
				//Yiran's logic: for incoming tcp traffic, we only process VMS enable packet
				if (likely(tcp->res1 & OVS_VMS_ENABLE)) {
					u16 truesrcport = getTrueSrcPort(tcp);
					cCh = ntohs(tcp->source);
                    /*csum_replace2(&tcp->check,tcp->source, htons(truesrcport));*/

					//Yiran's logic: here we modify the source port and also the key!!!!!!!!!!!!!!!
					tcp->source = htons(truesrcport);
					key->tp.src = tcp->source;


                    
				if (unlikely(tcp->syn)) {
					struct rcv_data * new_entry = NULL;
					struct rcv_ack * ack_entry2 = NULL;

                    //clear the vms mark,since the first incoming syn will miss the flow table. 
                    ipv4_change_dsfield(nh, 0, OVS_ECN_ZERO);
                    /*csum_replace2(&tcp->check, htons(tcp->res1 << 12), htons((tcp->res1 & OVS_VMS_CLEAR)<<12));*/
                    //tcp->res1 &= OVS_VMS_CLEAR;

					tcp_key64 = get_tcp_key64(srcip, dstip, truesrcport, dstport);
					rcu_read_lock();
                    new_entry = rcv_data_hashtbl_lookup(tcp_key64);
					rcu_read_unlock();

                    if (likely(!new_entry)) {
                        new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);	
						new_entry->key = tcp_key64;
						spin_lock_init(&new_entry->lock);
						rcv_data_hashtbl_insert(tcp_key64, new_entry);
						spin_lock(&new_entry->lock);
						new_entry->expected = ntohl(tcp->seq) + 1;
                        //printk("insert entry in rcv_data_hashtbl.expected:%u.\n",new_entry->expected);
                        new_entry->FEEDBACK = 0;
						new_entry->reorder = 0;
						new_entry->skey = NULL;
						new_entry->dp = dp;
						new_entry->flow = NULL;
						new_entry->order_tree = NULL;
						for(index = 0 ; index < VMS_CHANNEL_NUM ; index ++)
						{
							new_entry->Channels[index].RttSize = 0;
							new_entry->Channels[index].RttCESize = 0;
							new_entry->Channels[index].LocalSendSeq = 0;
							new_entry->Channels[index].LocalFBKSeq = 0;
							new_entry->Channels[index].LocalRecvSeq = 0;
							new_entry->Channels[index].receivedCount = 0;
							new_entry->Channels[index].rwnd = RWND_INIT;
							new_entry->Channels[index].rwnd_ssthresh = RWND_SSTHRESH_INIT;//infinite
							new_entry->Channels[index].alpha = DCTCP_ALPHA_INIT;
							new_entry->Channels[index].flags = 0;
                            new_entry->Channels[index].lossdetected = false;
                            
						}
						spin_unlock(&new_entry->lock);
						//printk(KERN_INFO "rcv_data_hashtbl new entry inserted. %d --> %d\n", truesrcport, dstport);
					}
					tcp_key64 = get_tcp_key64(srcip, dstip, truesrcport, dstport);
					rcu_read_lock();
					ack_entry2 = rcv_ack_hashtbl_lookup(tcp_key64);
					rcu_read_unlock();
					if (!ack_entry2) {
						ack_entry2 = kzalloc(sizeof(*ack_entry2), GFP_KERNEL);
						ack_entry2->key = tcp_key64;
						rcv_ack_hashtbl_insert(tcp_key64, ack_entry2);

					}
					ack_entry2->snd_wscale = ovs_tcp_parse_options(skb);
					//printk("incoming SYN, get the window scaling factor and insert in rcv_ack_hashbtl: %u, src %u-->dest %u, MSS is %u\n",	ack_entry2->snd_wscale, truesrcport, ntohs(tcp->dest), MSS);	
					
				}
				/*TODO: we may also need to consider RST */
				if (unlikely(tcp->fin || tcp->rst)) {
					//printk(KERN_INFO "This FIN packet coming from the NIC,delete the entry in rcv_data_hashtbl. %d --> %d,\n",srcport, dstport);
					struct rcv_data * the_entry = NULL;
                    tcp_key64 = get_tcp_key64(srcip, dstip, truesrcport, dstport);
					rcu_read_lock();
                    the_entry = rcv_data_hashtbl_lookup(tcp_key64);
					rcu_read_unlock();
					if (likely(the_entry)) {
						rcv_data_hashtbl_delete(the_entry);
						//printk(KERN_INFO "rcv_data_hashtbl new entry deleted. %d --> %d\n",truesrcport, dstport);
					}
					else {
						//printk(KERN_INFO "rcv_data_hashtbl try to delete but entry not found.	%d --> %d\n", srcport, dstport);
					}	
				}
				}//VMS enable packets	
			}//incoming to the host traffic
				
		}//is TCP packet
	}//is IP packet


	/* Look up flow. */
	flow = ovs_flow_tbl_lookup_stats(&dp->table, key, skb_get_hash(skb),
					 &n_mask_hit);
	if (unlikely(!flow)) {
		struct dp_upcall_info upcall;
		int error;
		memset(&upcall, 0, sizeof(upcall));
		upcall.cmd = OVS_PACKET_CMD_MISS;
		upcall.portid = ovs_vport_find_upcall_portid(p, skb);
		upcall.mru = OVS_CB(skb)->mru;
		error = ovs_dp_upcall(dp, skb, key, &upcall, 0);
		if (unlikely(error))
			kfree_skb(skb);
		else
			consume_skb(skb);
		stats_counter = &stats->n_missed;
		goto out;
	}

	u64 key64 = 0;
	if(ntohs(skb->protocol) == ETH_P_IP) {//this is an IP packet
		nh = ip_hdr(skb);
		if(nh->protocol == IPPROTO_TCP) {//this is an TCP packet
			u32 srcip;
			u32 dstip;
			u16 srcport;
			u16 dstport;
			u64 tcp_key64;

			//Yiran's logic:default channel,using when reset
			int cid = 0;
            int lossch = 8;	
			tcp = tcp_hdr(skb);
			srcip = ntohl(nh->saddr);
			dstip = ntohl(nh->daddr);
			//Yiran's logic: here the srcport is the true srcport  
			srcport = ntohs(tcp->source);
			dstport = ntohs(tcp->dest);
			//do not process SYN, SYN/ACK and FIN here
			if (likely(!(tcp->syn || tcp->fin))) {
				//process outgoing traffic
				if (ovs_packet_to_net(skb)) {
					int tcp_data_len;
					u16 psize;
					u32 end_seq;
					struct rcv_ack * the_entry = NULL;
                    bool retransmission =  false;
					//printk(KERN_INFO "This packet is outgoing, choose channel and update.(%d --> %d)\n",srcport, dstport);
					tcp_data_len = ntohs(nh->tot_len) - (nh->ihl << 2) - (tcp->doff << 2);
					psize = tcp_data_len;
					end_seq = ntohl(tcp->seq) + tcp_data_len;
					tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);
					rcu_read_lock();
					the_entry = rcv_ack_hashtbl_lookup(tcp_key64);
					if (likely(the_entry)) {
						spin_lock(&the_entry->lock);
                        //add by Yiran 2017 11 11: we only choose channel for data packets
                        
                        if(tcp_data_len > 0 && before(end_seq,the_entry->snd_nxt))
                        {
                            //printk(KERN_INFO "packet size: %u. \n",ntohs(nh->tot_len));
                            //printk(KERN_INFO "retransmission packet. there is packet loss? ntohl(tcp->seq):%u, the_entry->snd_nxt: %u. \n",ntohl(tcp->seq),the_entry->snd_nxt);
                            //We consider a retransmission is caused by packet loss
                            //the_entry->Flags |= VMS_SIN_FLAG;
                            retransmission = true;

                        }
                        else if(tcp_data_len > 0 && (after(end_seq,the_entry->snd_nxt) || (end_seq == the_entry->snd_nxt)))
                        {
                            the_entry->snd_nxt = end_seq;
                        }

                        if(the_entry->Flags & VMS_SIN_FLAG){
                            //lossch = FindLossChannel(ntohl(tcp->seq),the_entry->seq_chain);
                            if(lossch < 8)
                            {
                                the_entry->Channels[lossch].lossdetected = true;
                            }
                            else
                            {
                                //printk("We don't find the channel has loss packet");
                            }

                        }
						cid = Window_based_Channel_Choosing(the_entry,psize);
                        /*if(retransmission == false && tcp_data_len > 0)
                        {
                            insertToSeqList(the_entry,ntohl(tcp->seq),cid);
                            if(the_entry->seq_chain == NULL)
                            {
                                printk("seq_chain is null!!!!\n");
                            }
                            
                        }*/

                        //csum_replace2(&tcp->check,tcp->source, htons(((srcport - cid) & 7)+ ((srcport & (~7)))));
						//tcp->source = htons(((srcport - cid) & 7)+ ((srcport & (~7))));
                        tcp->source = htons(srcport + cid);
                        //csum_replace2(&tcp->check, htons(tcp->res1 << 12), htons(tcp->res1 | (cid << 1) << 12));
                        tcp->res1 |= (cid << 1);
						spin_unlock(&the_entry->lock);
					}
					rcu_read_unlock();
					/*third task, may 1)pack ecn info into a PACK*/		
					if (tcp->ack) {
//						printk("return ack:%u\n", ntohl(tcp->ack_seq));
						struct rcv_data * byte_entry = NULL;
						u16 fbkid;
						u16 RecevivedCount = 0;
						u32 FbkNumber;
						u16 RCE = 0 ;
						int n = 0;
						//tcp_key64 calculated above
						rcu_read_lock();
						byte_entry = rcv_data_hashtbl_lookup(tcp_key64);
						rcu_read_unlock();
						if (likely(byte_entry)) {
							//printk("begin process:outgoing ack:%u.  seq: %u \n",ntohl(tcp->ack_seq),ntohl(tcp->seq));
							spin_lock(&byte_entry->lock);
							//byte_entry->expected = ntohl(tcp->ack_seq);
							rcu_read_lock();
							the_entry = rcv_ack_hashtbl_lookup(tcp_key64);
							rcu_read_unlock();
							if(likely(the_entry))
							{
                                //Yiran: detect packet loss
								if(the_entry->Flags & VMS_SIN_FLAG)
								{
									fbkid = 0;
									RecevivedCount = byte_entry->Channels[fbkid].receivedCount;
								}
								else
								{
									fbkid = byte_entry->FEEDBACK;
									n = 0;
									RecevivedCount = byte_entry -> Channels[fbkid].receivedCount;
									while(n < VMS_CHANNEL_NUM)
									{
                                        if(byte_entry->Channels[fbkid].receivedCount > 0)
                                        {
                                            byte_entry->FEEDBACK = (fbkid + 1) & 7;
                                            break;
                                        }
										fbkid = (fbkid + 1) & 7;
										RecevivedCount = byte_entry->Channels[fbkid].receivedCount;
										n++;
									}
									//printk("packing channel:%u,RecevivedCount:%u\n",fbkid,RecevivedCount);
								}
								FbkNumber = byte_entry->Channels[fbkid].LocalRecvSeq;
								RCE = byte_entry->Channels[fbkid].flags & VMS_CHANNEL_RCE;
                                if (RCE == 0) {
                                    //printk("no rce feedback\n");
                                }
							}

                            //Yiran: only pure acks piggyback, to avoid packet length exceeding MTU
                            
							if(RecevivedCount > 0 && tcp_data_len < 1400/*tcp_data_len <= 1440*/)
							{
								int err;
								//printk("ReceiveCount:%u.fbkid:%u\n",RecevivedCount, fbkid);
								err = ovs_pack_FBK_info(skb,RecevivedCount,FbkNumber,RCE,fbkid);
                                //printk("tcp_data_len:%u.\n",tcp_data_len);
								byte_entry->Channels[fbkid].flags &= (~VMS_CHANNEL_RCE);
								//printk("ovs_pack_FBK_info:outgoing ack:%u.\n",ntohl(tcp->ack_seq));
								if (err)
								{
									printk(KERN_INFO "warning, packing feedback info error! outgoing ack:%u.\n",ntohl(tcp->ack_seq));
								}
								else //add by yiran 2017.11.9 : only when add option successfully, updata the entry
								{									
									byte_entry->Channels[fbkid].receivedCount = 0;
								}
							}	
							
							spin_unlock(&byte_entry->lock);

						}	
					}


				}//end processing outgoing skb
                else {
                    // processing incoming (to the end host) skbs
                    if(likely(tcp -> res1 & OVS_VMS_ENABLE)){
                        int tcp_data_len;
                        struct rcv_data * the_entry = NULL;
                        struct rcv_ack * ack_entry = NULL;
                        u8 ChannelID = tcp->res1 >> 1;
                        u32 seq_ack = ntohl(tcp->ack_seq);
                        u32 seq = ntohl(tcp->seq);
                        tcp_data_len = ntohs(nh->tot_len) - (nh->ihl << 2) - (tcp->doff << 2);
                        tcp_key64 = get_tcp_key64(srcip, dstip, srcport, dstport);
                        key64 = tcp_key64;

                        rcu_read_lock();
                        the_entry = rcv_data_hashtbl_lookup(tcp_key64);
                        rcu_read_unlock();
                        
                        if(likely(the_entry))
                        {
                            spin_lock(&the_entry->lock);
                            if(tcp_data_len > 0)
                            {
                                if(the_entry->expected == seq && the_entry->reorder == 0) //in-order packets
                                {
                                    the_entry->expected = seq + tcp_data_len;
                                    //printk("update the_entry->expected:%u, seq:%u, tcp_data_len:%u. \n",the_entry->expected, seq,tcp_data_len);

                                }
                                else
                                {
                                    the_entry->reorder = 1;
                                    //reorder = 1; //add to buffer
                                    //printk("!!!!!!!!!!!!the_entry->expected:%u, receive seq:%u, tcp_data_len:%u. \n",the_entry->expected, seq,tcp_data_len);
                                }
                                //expected = seq + tcp_data_len; // expected next data packet
                                the_entry->Channels[ChannelID].receivedCount += tcp_data_len;
                                the_entry->Channels[ChannelID].LocalRecvSeq += tcp_data_len;
                                if((nh->tos & OVS_ECN_MASK) == OVS_ECN_MASK)// receive a packet with ECN mark
                                {
                                    the_entry->Channels[ChannelID].flags |= VMS_CHANNEL_RCE;
                                }
                                else
                                {
                                    //printk("receive not ce packet.\n");
                                    the_entry->Channels[ChannelID].flags &= VMS_CHANNEL_RCE_CLEAR;
                                }					 
                            }
                            spin_unlock(&the_entry->lock);
                        }

                        rcu_read_lock();
                        ack_entry = rcv_ack_hashtbl_lookup(tcp_key64);
                        rcu_read_unlock();

                        //Yiran's logic:receive a packet with SIN flag, save in the rcv_ack table
                        if(likely(ack_entry))
                        {
                            spin_lock(&ack_entry->lock);
                            if(tcp->ece)
                            {
                                printk("what?\n");
                                //ack_entry->Flags |= VMS_SIN_FLAG; 
                            }
                            spin_unlock(&ack_entry->lock);
                        }

                        //second, if it is an ACK, 
                        //   i) update "snd_una" in "rcv_ack"
                        //  ii) run VJ congestion control algorithm and DCTCP logic
                        if (tcp->ack) {
                            struct rcv_ack * the_entry = NULL;
                            bool is_pack = false;
                            u32 fbkNumer = 0;
                            u32 receivedCount = 0;
                            u32 acked = 0;
                            u8 isRCE = 0;
                            u8 fbkcid = 0;

                            //Yiran's logic : PACK  FBK ---->CWR
                            if (tcp->cwr) {
                                int err;
                                is_pack = true;
                                err = ovs_unpack_FBK_info(skb, &fbkNumer, &receivedCount,&isRCE,&fbkcid);
                                //printk("ovs_unpack_FBK_info:fbkNumer:%u,receivedCount:%u,isRCE:%u,fbkcid:%u.\n",fbkNumer,receivedCount,isRCE,fbkcid);
                                if (err){
                                    printk(KERN_INFO "warning, unpack packet error\n");
                                    is_pack = false;
				    			}
								//printk("unpack: srcip:%u,dstip:%u,srcport:%u,destport:%u,isRCE:%u,FbkNmber:%u,fbkcid:%u.\n",srcip,dstip,srcport,dstport,isRCE,fbkNumer,fbkcid);
                                nh = ip_hdr(skb);
                                tcp = tcp_hdr(skb);

                            }
                            rcu_read_lock();
                            the_entry = rcv_ack_hashtbl_lookup(tcp_key64);
                            rcu_read_unlock();

                            if (likely(the_entry)) {
                                spin_lock(&the_entry->lock);

                                acked = ntohl(tcp->ack_seq) - the_entry->snd_una;
                                //printk(KERN_INFO "real ack acked bytes:%u, (%d --> %d)\n",acked, srcport, dstport);
                                the_entry->snd_una = ntohl(tcp->ack_seq);
                                if (fbkcid >= 8) {
                                    printk("error! fbkcid=%u   8!!\n", fbkcid);
                                }
                                
                                if (acked == 0 && before(the_entry->snd_una,the_entry->snd_nxt) && (tcp_data_len == 0)) {
                                    //printk("Duplicated ACK!!!!!, ack_seq:%u, expectd:%u, fbkcid:%u, receivedCount:%u, isRCE:%u. \n", ntohl(tcp->ack_seq),the_entry->snd_una, fbkcid,receivedCount,isRCE);
                                    the_entry->dupack_cnt ++;
                                } else {
                                    the_entry->dupack_cnt = 0;
                                    //freeChain(the_entry->seq_chain,ntohl(tcp->ack_seq),the_entry);
                                }
                                if (is_pack) {  
                                    OnFeedBack(the_entry,fbkcid,receivedCount,fbkNumer,isRCE,seq_ack);
                                }
                                //Yiran: when receive RCE feedback, we know which channel encounters congesiton but when packet lost, we don't know which channel lost packet!!!!!!
                                if(the_entry->dupack_cnt >= 3)
                                {
                                    if(the_entry->dupack_cnt >= 3)
                                    {
                                        the_entry->dupack_cnt = 0;
                                        //the_entry->Flags |= VMS_SIN_FLAG;
                                        printk("imcoming packet: dupack_cnt >=3\n");
                                    }
                                        
                                        
                                }
                               
                                //printk(KERN_INFO "begin rwnd enforce: \n");
                                //printk("incoming ACK, win scale is %u\n", the_entry->snd_wscale);	
                                //rwnd enforce put here
                                if ( (ntohs(tcp->window) << the_entry->snd_wscale) > the_entry->rwnd){
                                    u16 enforce_win = the_entry->rwnd >> the_entry->snd_wscale;
                                    //printk("ntohs(tcp->window):%u,enforce_win:%u.\n",ntohs(tcp->window),enforce_win);
                                    /*csum_replace2(&tcp->check,tcp->window, htons(enforce_win));*/
                                    //tcp->window = htons(enforce_win);
                                    //printk(KERN_INFO "update tcp->window %d\n", enforce_win);
                                }


                                spin_unlock(&the_entry->lock);

                            }

                        }




                    }	
                }
            }//end processing incoming SKB
        }//it was an TCP skb
    }//it was an IP skb


    /*keqiang's logic: marking*/
    /*here we assume that user won't use TOS field, in other words,
      it is always 0. For producation code, this can be solved by adding 
      a few more lines of code
     */
    //struct sk_buff *newskb = NULL;
    struct rcv_data * the_entry = NULL;
    if(ntohs(skb->protocol) == ETH_P_IP)
    {
        nh = ip_hdr(skb);
        if(nh->protocol == IPPROTO_TCP) {//this is an TCP packet
            tcp = tcp_hdr(skb);
            if (ovs_packet_to_net(skb)) {// outgoing to the NIC, enable VMS and ECN
                /*csum_replace2(&tcp->check, htons(tcp->res1 << 12), htons((tcp->res1 | OVS_VMS_ENABLE) << 12));*/
                tcp->res1 |= OVS_VMS_ENABLE;
                if ( (nh->tos & OVS_ECN_MASK) == OVS_ECN_ZERO) {//get the last 2 bits 
                    ipv4_change_dsfield(nh, 0, OVS_ECN_ONE);
                }
                if(tcp->psh == 1)
                {
                    //tcp->psh = 0;
                }
                //if(skb_is_nonlinear(skb))
                    //skb_linearize(skb);
                /*header_len = (ntohs(nh->tot_len) - (nh->ihl << 2));
                tcp->check = 0;
                tcp->check = tcp_v4_check(header_len,nh->saddr,nh->daddr,csum_partial((char*) tcp, header_len, 0));*/
                //printk(KERN_INFO "out : skb->ip_summed:%d,tcp->check:%02x, seq:%u.\n",skb->ip_summed,ntohs(tcp->check),ntohl(tcp->seq));

            }
            else {
                //Yiran's logic: imcoming packet, clear the mark
                if ( (nh->tos & OVS_ECN_MASK) != OVS_ECN_ZERO && (tcp->res1 & OVS_VMS_ENABLE) == OVS_VMS_ENABLE )
                {
                    ipv4_change_dsfield(nh, 0, OVS_ECN_ZERO);                  
                    /*csum_replace2(&tcp->check, htons(tcp->res1 << 12), htons((tcp->res1 & 0) << 12));*/
                    tcp->res1 &= 0;
                }

                if (tcp->ece)   //SIN
                {                    
                    /*csum_replace2(&tcp->check, htons(tcp->ece << 15), htons(0));*/
                    tcp->ece = 0;
                }
                if(tcp->cwr)    //FBK
                { 
                    /*csum_replace2(&tcp->check, htons(tcp->cwr << 15), htons(0));*/
                    tcp->cwr = 0;
                }
                //if(skb_is_nonlinear(skb))
                    //skb_linearize(skb);
                /*header_len = (ntohs(nh->tot_len) - (nh->ihl << 2));
                tcp->check = 0;
                tcp->check = tcp_v4_check(header_len,nh->saddr,nh->daddr,csum_partial((char*) tcp, header_len, 0));*/
                //printk(KERN_INFO "in : skb->ip_summed:%d,tcp->check:%02x, seq:%u.\n",skb->ip_summed,ntohs(tcp->check),ntohl(tcp->seq));

                rcu_read_lock();
                the_entry = rcv_data_hashtbl_lookup(key64);
                tmp_entry = the_entry;
                rcu_read_unlock();

                if(likely(the_entry) && reorder == 1)
                {
                    
                    spin_lock(&the_entry->lock);
                    //newskb = skb;
                    if(skb != NULL)
                    {
                        addToBuffer(key, skb, flow, dp, the_entry);
                        //printk("add to reorder buffer.\n");
                    }
                    else 
                    {
                        printk("add to buffer failure!.\n");
                    }
                    spin_unlock(&the_entry->lock);
                }
            }
            
        }//it was an TCP packet
    }//it was an IP packet


    ovs_flow_stats_update(flow, key->tp.flags, skb);
    sf_acts = rcu_dereference(flow->sf_acts);
    if(reorder == 0) {
        ovs_execute_actions(dp, skb, sf_acts, key);
    } else {
        
        /*if (tmp_entry != NULL) {
            spin_lock(&tmp_entry->lock);
            if (tmp_entry->order_tree != NULL) {
                BufferDump(tmp_entry->order_tree, tmp_entry);
            }
            spin_unlock(&tmp_entry->lock);
        }*/
    }

    stats_counter = &stats->n_hit;
out:
	/* Update datapath statistics. */
	u64_stats_update_begin(&stats->syncp);
	(*stats_counter)++;
	stats->n_mask_hit += n_mask_hit;
	u64_stats_update_end(&stats->syncp);
}

int ovs_dp_upcall(struct datapath *dp, struct sk_buff *skb,
		  const struct sw_flow_key *key,
		  const struct dp_upcall_info *upcall_info,
		  uint32_t cutlen)
{
	struct dp_stats_percpu *stats;
	int err;

	if (upcall_info->portid == 0) {
		err = -ENOTCONN;
		goto err;
	}

	if (!skb_is_gso(skb))
		err = queue_userspace_packet(dp, skb, key, upcall_info, cutlen);
	else
		err = queue_gso_packets(dp, skb, key, upcall_info, cutlen);
	if (err)
		goto err;

	return 0;

err:
	stats = this_cpu_ptr(dp->stats_percpu);

	u64_stats_update_begin(&stats->syncp);
	stats->n_lost++;
	u64_stats_update_end(&stats->syncp);

	return err;
}

static int queue_gso_packets(struct datapath *dp, struct sk_buff *skb,
			     const struct sw_flow_key *key,
			     const struct dp_upcall_info *upcall_info,
				 uint32_t cutlen)
{
	unsigned short gso_type = skb_shinfo(skb)->gso_type;
	struct sw_flow_key later_key;
	struct sk_buff *segs, *nskb;
	struct ovs_skb_cb ovs_cb;
	int err;

	ovs_cb = *OVS_CB(skb);
	segs = __skb_gso_segment(skb, NETIF_F_SG, false);
	*OVS_CB(skb) = ovs_cb;
	if (IS_ERR(segs))
		return PTR_ERR(segs);
	if (segs == NULL)
		return -EINVAL;

	if (gso_type & SKB_GSO_UDP) {
		/* The initial flow key extracted by ovs_flow_key_extract()
		 * in this case is for a first fragment, so we need to
		 * properly mark later fragments.
		 */
		later_key = *key;
		later_key.ip.frag = OVS_FRAG_TYPE_LATER;
	}

	/* Queue all of the segments. */
	skb = segs;
	do {
		*OVS_CB(skb) = ovs_cb;
		if (gso_type & SKB_GSO_UDP && skb != segs)
			key = &later_key;

		err = queue_userspace_packet(dp, skb, key, upcall_info, cutlen);
		if (err)
			break;

	} while ((skb = skb->next));

	/* Free all of the segments. */
	skb = segs;
	do {
		nskb = skb->next;
		if (err)
			kfree_skb(skb);
		else
			consume_skb(skb);
	} while ((skb = nskb));
	return err;
}

static size_t upcall_msg_size(const struct dp_upcall_info *upcall_info,
			      unsigned int hdrlen)
{
	size_t size = NLMSG_ALIGN(sizeof(struct ovs_header))
		+ nla_total_size(hdrlen) /* OVS_PACKET_ATTR_PACKET */
		+ nla_total_size(ovs_key_attr_size()) /* OVS_PACKET_ATTR_KEY */
		+ nla_total_size(sizeof(unsigned int)); /* OVS_PACKET_ATTR_LEN */

	/* OVS_PACKET_ATTR_USERDATA */
	if (upcall_info->userdata)
		size += NLA_ALIGN(upcall_info->userdata->nla_len);

	/* OVS_PACKET_ATTR_EGRESS_TUN_KEY */
	if (upcall_info->egress_tun_info)
		size += nla_total_size(ovs_tun_key_attr_size());

	/* OVS_PACKET_ATTR_ACTIONS */
	if (upcall_info->actions_len)
		size += nla_total_size(upcall_info->actions_len);

	/* OVS_PACKET_ATTR_MRU */
	if (upcall_info->mru)
		size += nla_total_size(sizeof(upcall_info->mru));

	return size;
}

static void pad_packet(struct datapath *dp, struct sk_buff *skb)
{
	if (!(dp->user_features & OVS_DP_F_UNALIGNED)) {
		size_t plen = NLA_ALIGN(skb->len) - skb->len;

		if (plen > 0)
			skb_put_zero(skb, plen);
	}
}

static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
				  const struct sw_flow_key *key,
				  const struct dp_upcall_info *upcall_info,
				  uint32_t cutlen)
{
	struct ovs_header *upcall;
	struct sk_buff *nskb = NULL;
	struct sk_buff *user_skb = NULL; /* to be queued to userspace */
	struct nlattr *nla;
	size_t len;
	unsigned int hlen;
	int err, dp_ifindex;

	dp_ifindex = get_dpifindex(dp);
	if (!dp_ifindex)
		return -ENODEV;

	if (skb_vlan_tag_present(skb)) {
		nskb = skb_clone(skb, GFP_ATOMIC);
		if (!nskb)
			return -ENOMEM;

		nskb = __vlan_hwaccel_push_inside(nskb);
		if (!nskb)
			return -ENOMEM;

		skb = nskb;
	}

	if (nla_attr_size(skb->len) > USHRT_MAX) {
		err = -EFBIG;
		goto out;
	}

	/* Complete checksum if needed */
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (err = skb_csum_hwoffload_help(skb, 0)))
		goto out;

	/* Older versions of OVS user space enforce alignment of the last
	 * Netlink attribute to NLA_ALIGNTO which would require extensive
	 * padding logic. Only perform zerocopy if padding is not required.
	 */
	if (dp->user_features & OVS_DP_F_UNALIGNED)
		hlen = skb_zerocopy_headlen(skb);
	else
		hlen = skb->len;

	len = upcall_msg_size(upcall_info, hlen - cutlen);
	user_skb = genlmsg_new(len, GFP_ATOMIC);
	if (!user_skb) {
		err = -ENOMEM;
		goto out;
	}

	upcall = genlmsg_put(user_skb, 0, 0, &dp_packet_genl_family,
			     0, upcall_info->cmd);
	upcall->dp_ifindex = dp_ifindex;

	err = ovs_nla_put_key(key, key, OVS_PACKET_ATTR_KEY, false, user_skb);
	BUG_ON(err);

	if (upcall_info->userdata)
		__nla_put(user_skb, OVS_PACKET_ATTR_USERDATA,
			  nla_len(upcall_info->userdata),
			  nla_data(upcall_info->userdata));


	if (upcall_info->egress_tun_info) {
		nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_EGRESS_TUN_KEY);
		err = ovs_nla_put_tunnel_info(user_skb,
					      upcall_info->egress_tun_info);
		BUG_ON(err);
		nla_nest_end(user_skb, nla);
	}

	if (upcall_info->actions_len) {
		nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_ACTIONS);
		err = ovs_nla_put_actions(upcall_info->actions,
					  upcall_info->actions_len,
					  user_skb);
		if (!err)
			nla_nest_end(user_skb, nla);
		else
			nla_nest_cancel(user_skb, nla);
	}

	/* Add OVS_PACKET_ATTR_MRU */
	if (upcall_info->mru) {
		if (nla_put_u16(user_skb, OVS_PACKET_ATTR_MRU,
				upcall_info->mru)) {
			err = -ENOBUFS;
			goto out;
		}
		pad_packet(dp, user_skb);
	}

	/* Add OVS_PACKET_ATTR_LEN when packet is truncated */
	if (cutlen > 0) {
		if (nla_put_u32(user_skb, OVS_PACKET_ATTR_LEN,
				skb->len)) {
			err = -ENOBUFS;
			goto out;
		}
		pad_packet(dp, user_skb);
	}

	/* Only reserve room for attribute header, packet data is added
	 * in skb_zerocopy()
	 */
	if (!(nla = nla_reserve(user_skb, OVS_PACKET_ATTR_PACKET, 0))) {
		err = -ENOBUFS;
		goto out;
	}
	nla->nla_len = nla_attr_size(skb->len - cutlen);

	err = skb_zerocopy(user_skb, skb, skb->len - cutlen, hlen);
	if (err)
		goto out;

	/* Pad OVS_PACKET_ATTR_PACKET if linear copy was performed */
	pad_packet(dp, user_skb);

	((struct nlmsghdr *) user_skb->data)->nlmsg_len = user_skb->len;

	err = genlmsg_unicast(ovs_dp_get_net(dp), user_skb, upcall_info->portid);
	user_skb = NULL;
out:
	if (err)
		skb_tx_error(skb);
	kfree_skb(user_skb);
	kfree_skb(nskb);
	return err;
}

static int ovs_packet_cmd_execute(struct sk_buff *skb, struct genl_info *info)
{
	struct ovs_header *ovs_header = info->userhdr;
	struct net *net = sock_net(skb->sk);
	struct nlattr **a = info->attrs;
	struct sw_flow_actions *acts;
	struct sk_buff *packet;
	struct sw_flow *flow;
	struct sw_flow_actions *sf_acts;
	struct datapath *dp;
	struct vport *input_vport;
	u16 mru = 0;
	int len;
	int err;
	bool log = !a[OVS_PACKET_ATTR_PROBE];

	err = -EINVAL;
	if (!a[OVS_PACKET_ATTR_PACKET] || !a[OVS_PACKET_ATTR_KEY] ||
	    !a[OVS_PACKET_ATTR_ACTIONS])
		goto err;

	len = nla_len(a[OVS_PACKET_ATTR_PACKET]);
	packet = __dev_alloc_skb(NET_IP_ALIGN + len, GFP_KERNEL);
	err = -ENOMEM;
	if (!packet)
		goto err;
	skb_reserve(packet, NET_IP_ALIGN);

	nla_memcpy(__skb_put(packet, len), a[OVS_PACKET_ATTR_PACKET], len);

	/* Set packet's mru */
	if (a[OVS_PACKET_ATTR_MRU]) {
		mru = nla_get_u16(a[OVS_PACKET_ATTR_MRU]);
		packet->ignore_df = 1;
	}
	OVS_CB(packet)->mru = mru;

	/* Build an sw_flow for sending this packet. */
	flow = ovs_flow_alloc();
	err = PTR_ERR(flow);
	if (IS_ERR(flow))
		goto err_kfree_skb;

	err = ovs_flow_key_extract_userspace(net, a[OVS_PACKET_ATTR_KEY],
					     packet, &flow->key, log);
	if (err)
		goto err_flow_free;

	err = ovs_nla_copy_actions(net, a[OVS_PACKET_ATTR_ACTIONS],
				   &flow->key, &acts, log);
	if (err)
		goto err_flow_free;

	rcu_assign_pointer(flow->sf_acts, acts);
	packet->priority = flow->key.phy.priority;
	packet->mark = flow->key.phy.skb_mark;

	rcu_read_lock();
	dp = get_dp_rcu(net, ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto err_unlock;

	input_vport = ovs_vport_rcu(dp, flow->key.phy.in_port);
	if (!input_vport)
		input_vport = ovs_vport_rcu(dp, OVSP_LOCAL);

	if (!input_vport)
		goto err_unlock;

	packet->dev = input_vport->dev;
	OVS_CB(packet)->input_vport = input_vport;
	sf_acts = rcu_dereference(flow->sf_acts);

	local_bh_disable();
	err = ovs_execute_actions(dp, packet, sf_acts, &flow->key);
	local_bh_enable();
	rcu_read_unlock();

	ovs_flow_free(flow, false);
	return err;

err_unlock:
	rcu_read_unlock();
err_flow_free:
	ovs_flow_free(flow, false);
err_kfree_skb:
	kfree_skb(packet);
err:
	return err;
}

static const struct nla_policy packet_policy[OVS_PACKET_ATTR_MAX + 1] = {
	[OVS_PACKET_ATTR_PACKET] = { .len = ETH_HLEN },
	[OVS_PACKET_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_PROBE] = { .type = NLA_FLAG },
	[OVS_PACKET_ATTR_MRU] = { .type = NLA_U16 },
};

static struct genl_ops dp_packet_genl_ops[] = {
	{ .cmd = OVS_PACKET_CMD_EXECUTE,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = packet_policy,
	  .doit = ovs_packet_cmd_execute
	}
};

static struct genl_family dp_packet_genl_family __ro_after_init = {
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_PACKET_FAMILY,
	.version = OVS_PACKET_VERSION,
	.maxattr = OVS_PACKET_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_packet_genl_ops,
	.n_ops = ARRAY_SIZE(dp_packet_genl_ops),
	.module = THIS_MODULE,
};

static void get_dp_stats(const struct datapath *dp, struct ovs_dp_stats *stats,
			 struct ovs_dp_megaflow_stats *mega_stats)
{
	int i;

	memset(mega_stats, 0, sizeof(*mega_stats));

	stats->n_flows = ovs_flow_tbl_count(&dp->table);
	mega_stats->n_masks = ovs_flow_tbl_num_masks(&dp->table);

	stats->n_hit = stats->n_missed = stats->n_lost = 0;

	for_each_possible_cpu(i) {
		const struct dp_stats_percpu *percpu_stats;
		struct dp_stats_percpu local_stats;
		unsigned int start;

		percpu_stats = per_cpu_ptr(dp->stats_percpu, i);

		do {
			start = u64_stats_fetch_begin_irq(&percpu_stats->syncp);
			local_stats = *percpu_stats;
		} while (u64_stats_fetch_retry_irq(&percpu_stats->syncp, start));

		stats->n_hit += local_stats.n_hit;
		stats->n_missed += local_stats.n_missed;
		stats->n_lost += local_stats.n_lost;
		mega_stats->n_mask_hit += local_stats.n_mask_hit;
	}
}

static bool should_fill_key(const struct sw_flow_id *sfid, uint32_t ufid_flags)
{
	return ovs_identifier_is_ufid(sfid) &&
	       !(ufid_flags & OVS_UFID_F_OMIT_KEY);
}

static bool should_fill_mask(uint32_t ufid_flags)
{
	return !(ufid_flags & OVS_UFID_F_OMIT_MASK);
}

static bool should_fill_actions(uint32_t ufid_flags)
{
	return !(ufid_flags & OVS_UFID_F_OMIT_ACTIONS);
}

static size_t ovs_flow_cmd_msg_size(const struct sw_flow_actions *acts,
				    const struct sw_flow_id *sfid,
				    uint32_t ufid_flags)
{
	size_t len = NLMSG_ALIGN(sizeof(struct ovs_header));

	/* OVS_FLOW_ATTR_UFID */
	if (sfid && ovs_identifier_is_ufid(sfid))
		len += nla_total_size(sfid->ufid_len);

	/* OVS_FLOW_ATTR_KEY */
	if (!sfid || should_fill_key(sfid, ufid_flags))
		len += nla_total_size(ovs_key_attr_size());

	/* OVS_FLOW_ATTR_MASK */
	if (should_fill_mask(ufid_flags))
		len += nla_total_size(ovs_key_attr_size());

	/* OVS_FLOW_ATTR_ACTIONS */
	if (should_fill_actions(ufid_flags))
		len += nla_total_size(acts->orig_len);

	return len
		+ nla_total_size_64bit(sizeof(struct ovs_flow_stats)) /* OVS_FLOW_ATTR_STATS */
		+ nla_total_size(1) /* OVS_FLOW_ATTR_TCP_FLAGS */
		+ nla_total_size_64bit(8); /* OVS_FLOW_ATTR_USED */
}

/* Called with ovs_mutex or RCU read lock. */
static int ovs_flow_cmd_fill_stats(const struct sw_flow *flow,
				   struct sk_buff *skb)
{
	struct ovs_flow_stats stats;
	__be16 tcp_flags;
	unsigned long used;

	ovs_flow_stats_get(flow, &stats, &used, &tcp_flags);

	if (used &&
	    nla_put_u64_64bit(skb, OVS_FLOW_ATTR_USED, ovs_flow_used_time(used),
			      OVS_FLOW_ATTR_PAD))
		return -EMSGSIZE;

	if (stats.n_packets &&
	    nla_put_64bit(skb, OVS_FLOW_ATTR_STATS,
			  sizeof(struct ovs_flow_stats), &stats,
			  OVS_FLOW_ATTR_PAD))
		return -EMSGSIZE;

	if ((u8)ntohs(tcp_flags) &&
	     nla_put_u8(skb, OVS_FLOW_ATTR_TCP_FLAGS, (u8)ntohs(tcp_flags)))
		return -EMSGSIZE;

	return 0;
}

/* Called with ovs_mutex or RCU read lock. */
static int ovs_flow_cmd_fill_actions(const struct sw_flow *flow,
				     struct sk_buff *skb, int skb_orig_len)
{
	struct nlattr *start;
	int err;

	/* If OVS_FLOW_ATTR_ACTIONS doesn't fit, skip dumping the actions if
	 * this is the first flow to be dumped into 'skb'.  This is unusual for
	 * Netlink but individual action lists can be longer than
	 * NLMSG_GOODSIZE and thus entirely undumpable if we didn't do this.
	 * The userspace caller can always fetch the actions separately if it
	 * really wants them.  (Most userspace callers in fact don't care.)
	 *
	 * This can only fail for dump operations because the skb is always
	 * properly sized for single flows.
	 */
	start = nla_nest_start(skb, OVS_FLOW_ATTR_ACTIONS);
	if (start) {
		const struct sw_flow_actions *sf_acts;

		sf_acts = rcu_dereference_ovsl(flow->sf_acts);
		err = ovs_nla_put_actions(sf_acts->actions,
					  sf_acts->actions_len, skb);

		if (!err)
			nla_nest_end(skb, start);
		else {
			if (skb_orig_len)
				return err;

			nla_nest_cancel(skb, start);
		}
	} else if (skb_orig_len) {
		return -EMSGSIZE;
	}

	return 0;
}

/* Called with ovs_mutex or RCU read lock. */
static int ovs_flow_cmd_fill_info(const struct sw_flow *flow, int dp_ifindex,
				  struct sk_buff *skb, u32 portid,
				  u32 seq, u32 flags, u8 cmd, u32 ufid_flags)
{
	const int skb_orig_len = skb->len;
	struct ovs_header *ovs_header;
	int err;

	ovs_header = genlmsg_put(skb, portid, seq, &dp_flow_genl_family,
				 flags, cmd);
	if (!ovs_header)
		return -EMSGSIZE;

	ovs_header->dp_ifindex = dp_ifindex;

	err = ovs_nla_put_identifier(flow, skb);
	if (err)
		goto error;

	if (should_fill_key(&flow->id, ufid_flags)) {
		err = ovs_nla_put_masked_key(flow, skb);
		if (err)
			goto error;
	}

	if (should_fill_mask(ufid_flags)) {
		err = ovs_nla_put_mask(flow, skb);
		if (err)
			goto error;
	}

	err = ovs_flow_cmd_fill_stats(flow, skb);
	if (err)
		goto error;

	if (should_fill_actions(ufid_flags)) {
		err = ovs_flow_cmd_fill_actions(flow, skb, skb_orig_len);
		if (err)
			goto error;
	}

	genlmsg_end(skb, ovs_header);
	return 0;

error:
	genlmsg_cancel(skb, ovs_header);
	return err;
}

/* May not be called with RCU read lock. */
static struct sk_buff *ovs_flow_cmd_alloc_info(const struct sw_flow_actions *acts,
					       const struct sw_flow_id *sfid,
					       struct genl_info *info,
					       bool always,
					       uint32_t ufid_flags)
{
	struct sk_buff *skb;
	size_t len;

	if (!always && !ovs_must_notify(&dp_flow_genl_family, info,
					GROUP_ID(&ovs_dp_flow_multicast_group)))
		return NULL;

	len = ovs_flow_cmd_msg_size(acts, sfid, ufid_flags);
	skb = genlmsg_new(len, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	return skb;
}

/* Called with ovs_mutex. */
static struct sk_buff *ovs_flow_cmd_build_info(const struct sw_flow *flow,
					       int dp_ifindex,
					       struct genl_info *info, u8 cmd,
					       bool always, u32 ufid_flags)
{
	struct sk_buff *skb;
	int retval;

	skb = ovs_flow_cmd_alloc_info(ovsl_dereference(flow->sf_acts),
				      &flow->id, info, always, ufid_flags);
	if (IS_ERR_OR_NULL(skb))
		return skb;

	retval = ovs_flow_cmd_fill_info(flow, dp_ifindex, skb,
					info->snd_portid, info->snd_seq, 0,
					cmd, ufid_flags);
	BUG_ON(retval < 0);
	return skb;
}

static int ovs_flow_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow *flow = NULL, *new_flow;
	struct sw_flow_mask mask;
	struct sk_buff *reply;
	struct datapath *dp;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int error;
	bool log = !a[OVS_FLOW_ATTR_PROBE];

	/* Must have key and actions. */
	error = -EINVAL;
	if (!a[OVS_FLOW_ATTR_KEY]) {
		OVS_NLERR(log, "Flow key attr not present in new flow.");
		goto error;
	}
	if (!a[OVS_FLOW_ATTR_ACTIONS]) {
		OVS_NLERR(log, "Flow actions attr not present in new flow.");
		goto error;
	}

	/* Most of the time we need to allocate a new flow, do it before
	 * locking.
	 */
	new_flow = ovs_flow_alloc();
	if (IS_ERR(new_flow)) {
		error = PTR_ERR(new_flow);
		goto error;
	}

	/* Extract key. */
	ovs_match_init(&match, &new_flow->key, false, &mask);
	error = ovs_nla_get_match(net, &match, a[OVS_FLOW_ATTR_KEY],
				  a[OVS_FLOW_ATTR_MASK], log);
	if (error)
		goto err_kfree_flow;

	/* Extract flow identifier. */
	error = ovs_nla_get_identifier(&new_flow->id, a[OVS_FLOW_ATTR_UFID],
				       &new_flow->key, log);
	if (error)
		goto err_kfree_flow;

	/* unmasked key is needed to match when ufid is not used. */
	if (ovs_identifier_is_key(&new_flow->id))
		match.key = new_flow->id.unmasked_key;

	ovs_flow_mask_key(&new_flow->key, &new_flow->key, true, &mask);

	/* Validate actions. */
	error = ovs_nla_copy_actions(net, a[OVS_FLOW_ATTR_ACTIONS],
				     &new_flow->key, &acts, log);
	if (error) {
		OVS_NLERR(log, "Flow actions may not be safe on all matching packets.");
		goto err_kfree_flow;
	}

	reply = ovs_flow_cmd_alloc_info(acts, &new_flow->id, info, false,
					ufid_flags);
	if (IS_ERR(reply)) {
		error = PTR_ERR(reply);
		goto err_kfree_acts;
	}

	ovs_lock();
	dp = get_dp(net, ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		error = -ENODEV;
		goto err_unlock_ovs;
	}

	/* Check if this is a duplicate flow */
	if (ovs_identifier_is_ufid(&new_flow->id))
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &new_flow->id);
	if (!flow)
		flow = ovs_flow_tbl_lookup(&dp->table, &new_flow->key);
	if (likely(!flow)) {
		rcu_assign_pointer(new_flow->sf_acts, acts);

		/* Put flow in bucket. */
		error = ovs_flow_tbl_insert(&dp->table, new_flow, &mask);
		if (unlikely(error)) {
			acts = NULL;
			goto err_unlock_ovs;
		}

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(new_flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
		ovs_unlock();
	} else {
		struct sw_flow_actions *old_acts;

		/* Bail out if we're not allowed to modify an existing flow.
		 * We accept NLM_F_CREATE in place of the intended NLM_F_EXCL
		 * because Generic Netlink treats the latter as a dump
		 * request.  We also accept NLM_F_EXCL in case that bug ever
		 * gets fixed.
		 */
		if (unlikely(info->nlhdr->nlmsg_flags & (NLM_F_CREATE
							 | NLM_F_EXCL))) {
			error = -EEXIST;
			goto err_unlock_ovs;
		}
		/* The flow identifier has to be the same for flow updates.
		 * Look for any overlapping flow.
		 */
		if (unlikely(!ovs_flow_cmp(flow, &match))) {
			if (ovs_identifier_is_key(&flow->id))
				flow = ovs_flow_tbl_lookup_exact(&dp->table,
								 &match);
			else /* UFID matches but key is different */
				flow = NULL;
			if (!flow) {
				error = -ENOENT;
				goto err_unlock_ovs;
			}
		}
		/* Update actions. */
		old_acts = ovsl_dereference(flow->sf_acts);
		rcu_assign_pointer(flow->sf_acts, acts);

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
		ovs_unlock();

		ovs_nla_free_flow_actions_rcu(old_acts);
		ovs_flow_free(new_flow, false);
	}

	if (reply)
		ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
	return 0;

err_unlock_ovs:
	ovs_unlock();
	kfree_skb(reply);
err_kfree_acts:
	ovs_nla_free_flow_actions(acts);
err_kfree_flow:
	ovs_flow_free(new_flow, false);
error:
	return error;
}

/* Factor out action copy to avoid "Wframe-larger-than=1024" warning. */
static struct sw_flow_actions *get_flow_actions(struct net *net,
						const struct nlattr *a,
						const struct sw_flow_key *key,
						const struct sw_flow_mask *mask,
						bool log)
{
	struct sw_flow_actions *acts;
	struct sw_flow_key masked_key;
	int error;

	ovs_flow_mask_key(&masked_key, key, true, mask);
	error = ovs_nla_copy_actions(net, a, &masked_key, &acts, log);
	if (error) {
		OVS_NLERR(log,
			  "Actions may not be safe on all matching packets");
		return ERR_PTR(error);
	}

	return acts;
}

/* Factor out match-init and action-copy to avoid
 * "Wframe-larger-than=1024" warning. Because mask is only
 * used to get actions, we new a function to save some
 * stack space.
 *
 * If there are not key and action attrs, we return 0
 * directly. In the case, the caller will also not use the
 * match as before. If there is action attr, we try to get
 * actions and save them to *acts. Before returning from
 * the function, we reset the match->mask pointer. Because
 * we should not to return match object with dangling reference
 * to mask.
 * */
static int ovs_nla_init_match_and_action(struct net *net,
					 struct sw_flow_match *match,
					 struct sw_flow_key *key,
					 struct nlattr **a,
					 struct sw_flow_actions **acts,
					 bool log)
{
	struct sw_flow_mask mask;
	int error = 0;

	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(match, key, true, &mask);
		error = ovs_nla_get_match(net, match, a[OVS_FLOW_ATTR_KEY],
					  a[OVS_FLOW_ATTR_MASK], log);
		if (error)
			goto error;
	}

	if (a[OVS_FLOW_ATTR_ACTIONS]) {
		if (!a[OVS_FLOW_ATTR_KEY]) {
			OVS_NLERR(log,
				  "Flow key attribute not present in set flow.");
			return -EINVAL;
		}

		*acts = get_flow_actions(net, a[OVS_FLOW_ATTR_ACTIONS], key,
					 &mask, log);
		if (IS_ERR(*acts)) {
			error = PTR_ERR(*acts);
			goto error;
		}
	}

	/* On success, error is 0. */
error:
	match->mask = NULL;
	return error;
}

static int ovs_flow_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sw_flow *flow;
	struct sk_buff *reply = NULL;
	struct datapath *dp;
	struct sw_flow_actions *old_acts = NULL, *acts = NULL;
	struct sw_flow_match match;
	struct sw_flow_id sfid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int error = 0;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&sfid, a[OVS_FLOW_ATTR_UFID], log);
	if (!a[OVS_FLOW_ATTR_KEY] && !ufid_present) {
		OVS_NLERR(log,
			  "Flow set message rejected, Key attribute missing.");
		return -EINVAL;
	}

	error = ovs_nla_init_match_and_action(net, &match, &key, a,
					      &acts, log);
	if (error)
		goto error;

	if (acts) {
		/* Can allocate before locking if have acts. */
		reply = ovs_flow_cmd_alloc_info(acts, &sfid, info, false,
						ufid_flags);
		if (IS_ERR(reply)) {
			error = PTR_ERR(reply);
			goto err_kfree_acts;
		}
	}

	ovs_lock();
	dp = get_dp(net, ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		error = -ENODEV;
		goto err_unlock_ovs;
	}
	/* Check that the flow exists. */
	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &sfid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (unlikely(!flow)) {
		error = -ENOENT;
		goto err_unlock_ovs;
	}

	/* Update actions, if present. */
	if (likely(acts)) {
		old_acts = ovsl_dereference(flow->sf_acts);
		rcu_assign_pointer(flow->sf_acts, acts);

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
	} else {
		/* Could not alloc without acts before locking. */
		reply = ovs_flow_cmd_build_info(flow, ovs_header->dp_ifindex,
						info, OVS_FLOW_CMD_NEW, false,
						ufid_flags);

		if (unlikely(IS_ERR(reply))) {
			error = PTR_ERR(reply);
			goto err_unlock_ovs;
		}
	}

	/* Clear stats. */
	if (a[OVS_FLOW_ATTR_CLEAR])
		ovs_flow_stats_clear(flow);
	ovs_unlock();

	if (reply)
		ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
	if (old_acts)
		ovs_nla_free_flow_actions_rcu(old_acts);

	return 0;

err_unlock_ovs:
	ovs_unlock();
	kfree_skb(reply);
err_kfree_acts:
	ovs_nla_free_flow_actions(acts);
error:
	return error;
}

static int ovs_flow_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct net *net = sock_net(skb->sk);
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow;
	struct datapath *dp;
	struct sw_flow_match match;
	struct sw_flow_id ufid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int err = 0;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&ufid, a[OVS_FLOW_ATTR_UFID], log);
	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(&match, &key, true, NULL);
		err = ovs_nla_get_match(net, &match, a[OVS_FLOW_ATTR_KEY], NULL,
					log);
	} else if (!ufid_present) {
		OVS_NLERR(log,
			  "Flow get message rejected, Key attribute missing.");
		err = -EINVAL;
	}
	if (err)
		return err;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		err = -ENODEV;
		goto unlock;
	}

	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &ufid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (!flow) {
		err = -ENOENT;
		goto unlock;
	}

	reply = ovs_flow_cmd_build_info(flow, ovs_header->dp_ifindex, info,
					OVS_FLOW_CMD_NEW, true, ufid_flags);
	if (IS_ERR(reply)) {
		err = PTR_ERR(reply);
		goto unlock;
	}

	ovs_unlock();
	return genlmsg_reply(reply, info);
unlock:
	ovs_unlock();
	return err;
}

static int ovs_flow_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct net *net = sock_net(skb->sk);
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow = NULL;
	struct datapath *dp;
	struct sw_flow_match match;
	struct sw_flow_id ufid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int err;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&ufid, a[OVS_FLOW_ATTR_UFID], log);
	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(&match, &key, true, NULL);
		err = ovs_nla_get_match(net, &match, a[OVS_FLOW_ATTR_KEY],
					NULL, log);
		if (unlikely(err))
			return err;
	}

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		err = -ENODEV;
		goto unlock;
	}

	if (unlikely(!a[OVS_FLOW_ATTR_KEY] && !ufid_present)) {
		err = ovs_flow_tbl_flush(&dp->table);
		goto unlock;
	}

	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &ufid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (unlikely(!flow)) {
		err = -ENOENT;
		goto unlock;
	}

	ovs_flow_tbl_remove(&dp->table, flow);
	ovs_unlock();

	reply = ovs_flow_cmd_alloc_info(rcu_dereference_raw(flow->sf_acts),
					&flow->id, info, false, ufid_flags);

	if (likely(reply)) {
		if (likely(!IS_ERR(reply))) {
			rcu_read_lock();	/*To keep RCU checker happy. */
			err = ovs_flow_cmd_fill_info(flow, ovs_header->dp_ifindex,
						     reply, info->snd_portid,
						     info->snd_seq, 0,
						     OVS_FLOW_CMD_DEL,
						     ufid_flags);
			rcu_read_unlock();
			BUG_ON(err < 0);
			ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
		} else {
			genl_set_err(&dp_flow_genl_family, sock_net(skb->sk), 0,
				     GROUP_ID(&ovs_dp_flow_multicast_group), PTR_ERR(reply));

		}
	}

	ovs_flow_free(flow, true);
	return 0;
unlock:
	ovs_unlock();
	return err;
}

static int ovs_flow_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *a[__OVS_FLOW_ATTR_MAX];
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct table_instance *ti;
	struct datapath *dp;
	u32 ufid_flags;
	int err;

	err = genlmsg_parse(cb->nlh, &dp_flow_genl_family, a,
			    OVS_FLOW_ATTR_MAX, flow_policy, NULL);
	if (err)
		return err;
	ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);

	rcu_read_lock();
	dp = get_dp_rcu(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		rcu_read_unlock();
		return -ENODEV;
	}

	ti = rcu_dereference(dp->table.ti);
	for (;;) {
		struct sw_flow *flow;
		u32 bucket, obj;

		bucket = cb->args[0];
		obj = cb->args[1];
		flow = ovs_flow_tbl_dump_next(ti, &bucket, &obj);
		if (!flow)
			break;

		if (ovs_flow_cmd_fill_info(flow, ovs_header->dp_ifindex, skb,
					   NETLINK_CB(cb->skb).portid,
					   cb->nlh->nlmsg_seq, NLM_F_MULTI,
					   OVS_FLOW_CMD_NEW, ufid_flags) < 0)
			break;

		cb->args[0] = bucket;
		cb->args[1] = obj;
	}
	rcu_read_unlock();
	return skb->len;
}

static const struct nla_policy flow_policy[OVS_FLOW_ATTR_MAX + 1] = {
	[OVS_FLOW_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_MASK] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_CLEAR] = { .type = NLA_FLAG },
	[OVS_FLOW_ATTR_PROBE] = { .type = NLA_FLAG },
	[OVS_FLOW_ATTR_UFID] = { .type = NLA_UNSPEC, .len = 1 },
	[OVS_FLOW_ATTR_UFID_FLAGS] = { .type = NLA_U32 },
};

static struct genl_ops dp_flow_genl_ops[] = {
	{ .cmd = OVS_FLOW_CMD_NEW,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_new
	},
	{ .cmd = OVS_FLOW_CMD_DEL,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_del
	},
	{ .cmd = OVS_FLOW_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_get,
	  .dumpit = ovs_flow_cmd_dump
	},
	{ .cmd = OVS_FLOW_CMD_SET,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_set,
	},
};

static struct genl_family dp_flow_genl_family __ro_after_init = {
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_FLOW_FAMILY,
	.version = OVS_FLOW_VERSION,
	.maxattr = OVS_FLOW_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_flow_genl_ops,
	.n_ops = ARRAY_SIZE(dp_flow_genl_ops),
	.mcgrps = &ovs_dp_flow_multicast_group,
	.n_mcgrps = 1,
	.module = THIS_MODULE,
};

static size_t ovs_dp_cmd_msg_size(void)
{
	size_t msgsize = NLMSG_ALIGN(sizeof(struct ovs_header));

	msgsize += nla_total_size(IFNAMSIZ);
	msgsize += nla_total_size_64bit(sizeof(struct ovs_dp_stats));
	msgsize += nla_total_size_64bit(sizeof(struct ovs_dp_megaflow_stats));
	msgsize += nla_total_size(sizeof(u32)); /* OVS_DP_ATTR_USER_FEATURES */

	return msgsize;
}

/* Called with ovs_mutex. */
static int ovs_dp_cmd_fill_info(struct datapath *dp, struct sk_buff *skb,
				u32 portid, u32 seq, u32 flags, u8 cmd)
{
	struct ovs_header *ovs_header;
	struct ovs_dp_stats dp_stats;
	struct ovs_dp_megaflow_stats dp_megaflow_stats;
	int err;

	ovs_header = genlmsg_put(skb, portid, seq, &dp_datapath_genl_family,
				   flags, cmd);
	if (!ovs_header)
		goto error;

	ovs_header->dp_ifindex = get_dpifindex(dp);

	err = nla_put_string(skb, OVS_DP_ATTR_NAME, ovs_dp_name(dp));
	if (err)
		goto nla_put_failure;

	get_dp_stats(dp, &dp_stats, &dp_megaflow_stats);
	if (nla_put_64bit(skb, OVS_DP_ATTR_STATS, sizeof(struct ovs_dp_stats),
			  &dp_stats, OVS_DP_ATTR_PAD))
		goto nla_put_failure;

	if (nla_put_64bit(skb, OVS_DP_ATTR_MEGAFLOW_STATS,
			  sizeof(struct ovs_dp_megaflow_stats),
			  &dp_megaflow_stats, OVS_DP_ATTR_PAD))
		goto nla_put_failure;

	if (nla_put_u32(skb, OVS_DP_ATTR_USER_FEATURES, dp->user_features))
		goto nla_put_failure;

	genlmsg_end(skb, ovs_header);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, ovs_header);
error:
	return -EMSGSIZE;
}

static struct sk_buff *ovs_dp_cmd_alloc_info(void)
{
	return genlmsg_new(ovs_dp_cmd_msg_size(), GFP_KERNEL);
}

/* Called with rcu_read_lock or ovs_mutex. */
static struct datapath *lookup_datapath(struct net *net,
					const struct ovs_header *ovs_header,
					struct nlattr *a[OVS_DP_ATTR_MAX + 1])
{
	struct datapath *dp;

	if (!a[OVS_DP_ATTR_NAME])
		dp = get_dp(net, ovs_header->dp_ifindex);
	else {
		struct vport *vport;

		vport = ovs_vport_locate(net, nla_data(a[OVS_DP_ATTR_NAME]));
		dp = vport && vport->port_no == OVSP_LOCAL ? vport->dp : NULL;
	}
	return dp ? dp : ERR_PTR(-ENODEV);
}

static void ovs_dp_reset_user_features(struct sk_buff *skb, struct genl_info *info)
{
	struct datapath *dp;

	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	if (IS_ERR(dp))
		return;

	WARN(dp->user_features, "Dropping previously announced user features\n");
	dp->user_features = 0;
}

static void ovs_dp_change(struct datapath *dp, struct nlattr *a[])
{
	if (a[OVS_DP_ATTR_USER_FEATURES])
		dp->user_features = nla_get_u32(a[OVS_DP_ATTR_USER_FEATURES]);
}

static int ovs_dp_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct vport_parms parms;
	struct sk_buff *reply;
	struct datapath *dp;
	struct vport *vport;
	struct ovs_net *ovs_net;
	int err, i;

	err = -EINVAL;
	if (!a[OVS_DP_ATTR_NAME] || !a[OVS_DP_ATTR_UPCALL_PID])
		goto err;

	reply = ovs_dp_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	err = -ENOMEM;
	dp = kzalloc(sizeof(*dp), GFP_KERNEL);
	if (dp == NULL)
		goto err_free_reply;

	ovs_dp_set_net(dp, sock_net(skb->sk));

	/* Allocate table. */
	err = ovs_flow_tbl_init(&dp->table);
	if (err)
		goto err_free_dp;

	dp->stats_percpu = netdev_alloc_pcpu_stats(struct dp_stats_percpu);
	if (!dp->stats_percpu) {
		err = -ENOMEM;
		goto err_destroy_table;
	}

	dp->ports = kmalloc(DP_VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dp->ports) {
		err = -ENOMEM;
		goto err_destroy_percpu;
	}

	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++)
		INIT_HLIST_HEAD(&dp->ports[i]);

	/* Set up our datapath device. */
	parms.name = nla_data(a[OVS_DP_ATTR_NAME]);
	parms.type = OVS_VPORT_TYPE_INTERNAL;
	parms.options = NULL;
	parms.dp = dp;
	parms.port_no = OVSP_LOCAL;
	parms.upcall_portids = a[OVS_DP_ATTR_UPCALL_PID];

	ovs_dp_change(dp, a);

	/* So far only local changes have been made, now need the lock. */
	ovs_lock();

	vport = new_vport(&parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		if (err == -EBUSY)
			err = -EEXIST;

		if (err == -EEXIST) {
			/* An outdated user space instance that does not understand
			 * the concept of user_features has attempted to create a new
			 * datapath and is likely to reuse it. Drop all user features.
			 */
			if (info->genlhdr->version < OVS_DP_VER_FEATURES)
				ovs_dp_reset_user_features(skb, info);
		}

		goto err_destroy_ports_array;
	}

	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);

	ovs_net = net_generic(ovs_dp_get_net(dp), ovs_net_id);
	list_add_tail_rcu(&dp->list_node, &ovs_net->dps);

	ovs_unlock();

	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_destroy_ports_array:
	ovs_unlock();
	kfree(dp->ports);
err_destroy_percpu:
	free_percpu(dp->stats_percpu);
err_destroy_table:
	ovs_flow_tbl_destroy(&dp->table);
err_free_dp:
	kfree(dp);
err_free_reply:
	kfree_skb(reply);
err:
	return err;
}

/* Called with ovs_mutex. */
static void __dp_destroy(struct datapath *dp)
{
	int i;

	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;
		struct hlist_node *n;

		hlist_for_each_entry_safe(vport, n, &dp->ports[i], dp_hash_node)
			if (vport->port_no != OVSP_LOCAL)
				ovs_dp_detach_port(vport);
	}

	list_del_rcu(&dp->list_node);

	/* OVSP_LOCAL is datapath internal port. We need to make sure that
	 * all ports in datapath are destroyed first before freeing datapath.
	 */
	ovs_dp_detach_port(ovs_vport_ovsl(dp, OVSP_LOCAL));

	/* RCU destroy the flow table */
	call_rcu(&dp->rcu, destroy_dp_rcu);
}

static int ovs_dp_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto err_unlock_free;

	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_DEL);
	BUG_ON(err < 0);

	__dp_destroy(dp);
	ovs_unlock();

	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

static int ovs_dp_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto err_unlock_free;

	ovs_dp_change(dp, info->attrs);

	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);

	ovs_unlock();

	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

static int ovs_dp_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	if (IS_ERR(dp)) {
		err = PTR_ERR(dp);
		goto err_unlock_free;
	}
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);
	ovs_unlock();

	return genlmsg_reply(reply, info);

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

static int ovs_dp_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ovs_net *ovs_net = net_generic(sock_net(skb->sk), ovs_net_id);
	struct datapath *dp;
	int skip = cb->args[0];
	int i = 0;

	ovs_lock();
	list_for_each_entry(dp, &ovs_net->dps, list_node) {
		if (i >= skip &&
		    ovs_dp_cmd_fill_info(dp, skb, NETLINK_CB(cb->skb).portid,
					 cb->nlh->nlmsg_seq, NLM_F_MULTI,
					 OVS_DP_CMD_NEW) < 0)
			break;
		i++;
	}
	ovs_unlock();

	cb->args[0] = i;

	return skb->len;
}

static const struct nla_policy datapath_policy[OVS_DP_ATTR_MAX + 1] = {
	[OVS_DP_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_DP_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_DP_ATTR_USER_FEATURES] = { .type = NLA_U32 },
};

static struct genl_ops dp_datapath_genl_ops[] = {
	{ .cmd = OVS_DP_CMD_NEW,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_new
	},
	{ .cmd = OVS_DP_CMD_DEL,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_del
	},
	{ .cmd = OVS_DP_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_get,
	  .dumpit = ovs_dp_cmd_dump
	},
	{ .cmd = OVS_DP_CMD_SET,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_set,
	},
};

static struct genl_family dp_datapath_genl_family __ro_after_init = {
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_DATAPATH_FAMILY,
	.version = OVS_DATAPATH_VERSION,
	.maxattr = OVS_DP_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_datapath_genl_ops,
	.n_ops = ARRAY_SIZE(dp_datapath_genl_ops),
	.mcgrps = &ovs_dp_datapath_multicast_group,
	.n_mcgrps = 1,
	.module = THIS_MODULE,
};

/* Called with ovs_mutex or RCU read lock. */
static int ovs_vport_cmd_fill_info(struct vport *vport, struct sk_buff *skb,
				   u32 portid, u32 seq, u32 flags, u8 cmd)
{
	struct ovs_header *ovs_header;
	struct ovs_vport_stats vport_stats;
	int err;

	ovs_header = genlmsg_put(skb, portid, seq, &dp_vport_genl_family,
				 flags, cmd);
	if (!ovs_header)
		return -EMSGSIZE;

	ovs_header->dp_ifindex = get_dpifindex(vport->dp);

	if (nla_put_u32(skb, OVS_VPORT_ATTR_PORT_NO, vport->port_no) ||
	    nla_put_u32(skb, OVS_VPORT_ATTR_TYPE, vport->ops->type) ||
	    nla_put_string(skb, OVS_VPORT_ATTR_NAME,
			   ovs_vport_name(vport)))
		goto nla_put_failure;

	ovs_vport_get_stats(vport, &vport_stats);
	if (nla_put_64bit(skb, OVS_VPORT_ATTR_STATS,
			  sizeof(struct ovs_vport_stats), &vport_stats,
			  OVS_VPORT_ATTR_PAD))
		goto nla_put_failure;

	if (ovs_vport_get_upcall_portids(vport, skb))
		goto nla_put_failure;

	err = ovs_vport_get_options(vport, skb);
	if (err == -EMSGSIZE)
		goto error;

	genlmsg_end(skb, ovs_header);
	return 0;

nla_put_failure:
	err = -EMSGSIZE;
error:
	genlmsg_cancel(skb, ovs_header);
	return err;
}

static struct sk_buff *ovs_vport_cmd_alloc_info(void)
{
	return nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
}

/* Called with ovs_mutex, only via ovs_dp_notify_wq(). */
struct sk_buff *ovs_vport_cmd_build_info(struct vport *vport, u32 portid,
					 u32 seq, u8 cmd)
{
	struct sk_buff *skb;
	int retval;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	retval = ovs_vport_cmd_fill_info(vport, skb, portid, seq, 0, cmd);
	BUG_ON(retval < 0);

	return skb;
}

/* Called with ovs_mutex or RCU read lock. */
static struct vport *lookup_vport(struct net *net,
				  const struct ovs_header *ovs_header,
				  struct nlattr *a[OVS_VPORT_ATTR_MAX + 1])
{
	struct datapath *dp;
	struct vport *vport;

	if (a[OVS_VPORT_ATTR_NAME]) {
		vport = ovs_vport_locate(net, nla_data(a[OVS_VPORT_ATTR_NAME]));
		if (!vport)
			return ERR_PTR(-ENODEV);
		if (ovs_header->dp_ifindex &&
		    ovs_header->dp_ifindex != get_dpifindex(vport->dp))
			return ERR_PTR(-ENODEV);
		return vport;
	} else if (a[OVS_VPORT_ATTR_PORT_NO]) {
		u32 port_no = nla_get_u32(a[OVS_VPORT_ATTR_PORT_NO]);

		if (port_no >= DP_MAX_PORTS)
			return ERR_PTR(-EFBIG);

		dp = get_dp(net, ovs_header->dp_ifindex);
		if (!dp)
			return ERR_PTR(-ENODEV);

		vport = ovs_vport_ovsl_rcu(dp, port_no);
		if (!vport)
			return ERR_PTR(-ENODEV);
		return vport;
	} else
		return ERR_PTR(-EINVAL);
}

/* Called with ovs_mutex */
static void update_headroom(struct datapath *dp)
{
	unsigned dev_headroom, max_headroom = 0;
	struct net_device *dev;
	struct vport *vport;
	int i;

	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		hlist_for_each_entry_rcu(vport, &dp->ports[i], dp_hash_node) {
			dev = vport->dev;
			dev_headroom = netdev_get_fwd_headroom(dev);
			if (dev_headroom > max_headroom)
				max_headroom = dev_headroom;
		}
	}

	dp->max_headroom = max_headroom;
	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++)
		hlist_for_each_entry_rcu(vport, &dp->ports[i], dp_hash_node)
			netdev_set_rx_headroom(vport->dev, max_headroom);
}

static int ovs_vport_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct vport_parms parms;
	struct sk_buff *reply;
	struct vport *vport;
	struct datapath *dp;
	u32 port_no;
	int err;

	if (!a[OVS_VPORT_ATTR_NAME] || !a[OVS_VPORT_ATTR_TYPE] ||
	    !a[OVS_VPORT_ATTR_UPCALL_PID])
		return -EINVAL;

	port_no = a[OVS_VPORT_ATTR_PORT_NO]
		? nla_get_u32(a[OVS_VPORT_ATTR_PORT_NO]) : 0;
	if (port_no >= DP_MAX_PORTS)
		return -EFBIG;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
restart:
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto exit_unlock_free;

	if (port_no) {
		vport = ovs_vport_ovsl(dp, port_no);
		err = -EBUSY;
		if (vport)
			goto exit_unlock_free;
	} else {
		for (port_no = 1; ; port_no++) {
			if (port_no >= DP_MAX_PORTS) {
				err = -EFBIG;
				goto exit_unlock_free;
			}
			vport = ovs_vport_ovsl(dp, port_no);
			if (!vport)
				break;
		}
	}

	parms.name = nla_data(a[OVS_VPORT_ATTR_NAME]);
	parms.type = nla_get_u32(a[OVS_VPORT_ATTR_TYPE]);
	parms.options = a[OVS_VPORT_ATTR_OPTIONS];
	parms.dp = dp;
	parms.port_no = port_no;
	parms.upcall_portids = a[OVS_VPORT_ATTR_UPCALL_PID];

	vport = new_vport(&parms);
	err = PTR_ERR(vport);
	if (IS_ERR(vport)) {
		if (err == -EAGAIN)
			goto restart;
		goto exit_unlock_free;
	}

	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);

	if (netdev_get_fwd_headroom(vport->dev) > dp->max_headroom)
		update_headroom(dp);
	else
		netdev_set_rx_headroom(vport->dev, dp->max_headroom);

	ovs_unlock();

	ovs_notify(&dp_vport_genl_family, &ovs_dp_vport_multicast_group, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

static int ovs_vport_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	vport = lookup_vport(sock_net(skb->sk), info->userhdr, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_free;

	if (a[OVS_VPORT_ATTR_TYPE] &&
	    nla_get_u32(a[OVS_VPORT_ATTR_TYPE]) != vport->ops->type) {
		err = -EINVAL;
		goto exit_unlock_free;
	}

	if (a[OVS_VPORT_ATTR_OPTIONS]) {
		err = ovs_vport_set_options(vport, a[OVS_VPORT_ATTR_OPTIONS]);
		if (err)
			goto exit_unlock_free;
	}

	if (a[OVS_VPORT_ATTR_UPCALL_PID]) {
		struct nlattr *ids = a[OVS_VPORT_ATTR_UPCALL_PID];

		err = ovs_vport_set_upcall_portids(vport, ids);
		if (err)
			goto exit_unlock_free;
	}

	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);
	ovs_unlock();

	ovs_notify(&dp_vport_genl_family, &ovs_dp_vport_multicast_group, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

static int ovs_vport_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	bool must_update_headroom = false;
	struct nlattr **a = info->attrs;
	struct sk_buff *reply;
	struct datapath *dp;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	vport = lookup_vport(sock_net(skb->sk), info->userhdr, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_free;

	if (vport->port_no == OVSP_LOCAL) {
		err = -EINVAL;
		goto exit_unlock_free;
	}

	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_DEL);
	BUG_ON(err < 0);

	/* the vport deletion may trigger dp headroom update */
	dp = vport->dp;
	if (netdev_get_fwd_headroom(vport->dev) == dp->max_headroom)
		must_update_headroom = true;
	netdev_reset_rx_headroom(vport->dev);
	ovs_dp_detach_port(vport);

	if (must_update_headroom)
		update_headroom(dp);

	ovs_unlock();

	ovs_notify(&dp_vport_genl_family, &ovs_dp_vport_multicast_group, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

static int ovs_vport_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	rcu_read_lock();
	vport = lookup_vport(sock_net(skb->sk), ovs_header, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_free;
	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);
	rcu_read_unlock();

	return genlmsg_reply(reply, info);

exit_unlock_free:
	rcu_read_unlock();
	kfree_skb(reply);
	return err;
}

static int ovs_vport_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct datapath *dp;
	int bucket = cb->args[0], skip = cb->args[1];
	int i, j = 0;

	rcu_read_lock();
	dp = get_dp_rcu(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		rcu_read_unlock();
		return -ENODEV;
	}
	for (i = bucket; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;

		j = 0;
		hlist_for_each_entry_rcu(vport, &dp->ports[i], dp_hash_node) {
			if (j >= skip &&
			    ovs_vport_cmd_fill_info(vport, skb,
						    NETLINK_CB(cb->skb).portid,
						    cb->nlh->nlmsg_seq,
						    NLM_F_MULTI,
						    OVS_VPORT_CMD_NEW) < 0)
				goto out;

			j++;
		}
		skip = 0;
	}
out:
	rcu_read_unlock();

	cb->args[0] = i;
	cb->args[1] = j;

	return skb->len;
}

static const struct nla_policy vport_policy[OVS_VPORT_ATTR_MAX + 1] = {
	[OVS_VPORT_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_VPORT_ATTR_STATS] = { .len = sizeof(struct ovs_vport_stats) },
	[OVS_VPORT_ATTR_PORT_NO] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_TYPE] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_OPTIONS] = { .type = NLA_NESTED },
};

static struct genl_ops dp_vport_genl_ops[] = {
	{ .cmd = OVS_VPORT_CMD_NEW,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_new
	},
	{ .cmd = OVS_VPORT_CMD_DEL,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_del
	},
	{ .cmd = OVS_VPORT_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_get,
	  .dumpit = ovs_vport_cmd_dump
	},
	{ .cmd = OVS_VPORT_CMD_SET,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_set,
	},
};

struct genl_family dp_vport_genl_family __ro_after_init = {
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_VPORT_FAMILY,
	.version = OVS_VPORT_VERSION,
	.maxattr = OVS_VPORT_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_vport_genl_ops,
	.n_ops = ARRAY_SIZE(dp_vport_genl_ops),
	.mcgrps = &ovs_dp_vport_multicast_group,
	.n_mcgrps = 1,
	.module = THIS_MODULE,
};

static struct genl_family *dp_genl_families[] = {
	&dp_datapath_genl_family,
	&dp_vport_genl_family,
	&dp_flow_genl_family,
	&dp_packet_genl_family,
};

static void dp_unregister_genl(int n_families)
{
	int i;

	for (i = 0; i < n_families; i++)
		genl_unregister_family(dp_genl_families[i]);
}

static int __init dp_register_genl(void)
{
	int err;
	int i;

	for (i = 0; i < ARRAY_SIZE(dp_genl_families); i++) {

		err = genl_register_family(dp_genl_families[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	dp_unregister_genl(i);
	return err;
}

static int __net_init ovs_init_net(struct net *net)
{
	struct ovs_net *ovs_net = net_generic(net, ovs_net_id);

	INIT_LIST_HEAD(&ovs_net->dps);
	INIT_WORK(&ovs_net->dp_notify_work, ovs_dp_notify_wq);
	ovs_ct_init(net);
	ovs_netns_frags_init(net);
	ovs_netns_frags6_init(net);
	return 0;
}

static void __net_exit list_vports_from_net(struct net *net, struct net *dnet,
					    struct list_head *head)
{
	struct ovs_net *ovs_net = net_generic(net, ovs_net_id);
	struct datapath *dp;

	list_for_each_entry(dp, &ovs_net->dps, list_node) {
		int i;

		for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
			struct vport *vport;

			hlist_for_each_entry(vport, &dp->ports[i], dp_hash_node) {

				if (vport->ops->type != OVS_VPORT_TYPE_INTERNAL)
					continue;

				if (dev_net(vport->dev) == dnet)
					list_add(&vport->detach_list, head);
			}
		}
	}
}

static void __net_exit ovs_exit_net(struct net *dnet)
{
	struct datapath *dp, *dp_next;
	struct ovs_net *ovs_net = net_generic(dnet, ovs_net_id);
	struct vport *vport, *vport_next;
	struct net *net;
	LIST_HEAD(head);

	ovs_netns_frags6_exit(dnet);
	ovs_netns_frags_exit(dnet);
	ovs_ct_exit(dnet);
	ovs_lock();
	list_for_each_entry_safe(dp, dp_next, &ovs_net->dps, list_node)
		__dp_destroy(dp);

	rtnl_lock();
	for_each_net(net)
		list_vports_from_net(net, dnet, &head);
	rtnl_unlock();

	/* Detach all vports from given namespace. */
	list_for_each_entry_safe(vport, vport_next, &head, detach_list) {
		list_del(&vport->detach_list);
		ovs_dp_detach_port(vport);
	}

	ovs_unlock();

	cancel_work_sync(&ovs_net->dp_notify_work);
}

static struct pernet_operations ovs_net_ops = {
	.init = ovs_init_net,
	.exit = ovs_exit_net,
	.id   = &ovs_net_id,
	.size = sizeof(struct ovs_net),
};

static int __init dp_init(void)
{
	int err;

	BUILD_BUG_ON(sizeof(struct ovs_skb_cb) > FIELD_SIZEOF(struct sk_buff, cb));

	pr_info("Open vSwitch switching datapath %s\n", VERSION);

	err = action_fifos_init();
	if (err)
		goto error;

	err = ovs_internal_dev_rtnl_link_register();
	if (err)
		goto error_action_fifos_exit;

	err = ovs_flow_init();
	if (err)
		goto error_unreg_rtnl_link;

	err = ovs_vport_init();
	if (err)
		goto error_flow_exit;

	err = register_pernet_device(&ovs_net_ops);
	if (err)
		goto error_vport_exit;

	err = compat_init();
	if (err)
		goto error_netns_exit;

	err = register_netdevice_notifier(&ovs_dp_device_notifier);
	if (err)
		goto error_compat_exit;

	err = ovs_netdev_init();
	if (err)
		goto error_unreg_notifier;

	err = dp_register_genl();
	if (err < 0)
		goto error_unreg_netdev;

	return 0;

error_unreg_netdev:
	ovs_netdev_exit();
error_unreg_notifier:
	unregister_netdevice_notifier(&ovs_dp_device_notifier);
error_compat_exit:
	compat_exit();
error_netns_exit:
	unregister_pernet_device(&ovs_net_ops);
error_vport_exit:
	ovs_vport_exit();
error_flow_exit:
	ovs_flow_exit();
error_unreg_rtnl_link:
	ovs_internal_dev_rtnl_link_unregister();
error_action_fifos_exit:
	action_fifos_exit();
error:
	return err;
}

static void dp_cleanup(void)
{
	/*Yiran's logic*/
	del_timer_sync(&my_timer);
	__hashtbl_exit();
	/*Yiran's logic*/
	dp_unregister_genl(ARRAY_SIZE(dp_genl_families));
	ovs_netdev_exit();
	unregister_netdevice_notifier(&ovs_dp_device_notifier);
	compat_exit();
	unregister_pernet_device(&ovs_net_ops);
	rcu_barrier();
	ovs_vport_exit();
	ovs_flow_exit();
	ovs_internal_dev_rtnl_link_unregister();
	action_fifos_exit();
}

module_init(dp_init);
module_exit(dp_cleanup);

MODULE_DESCRIPTION("Open vSwitch switching datapath");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);
MODULE_ALIAS_GENL_FAMILY(OVS_DATAPATH_FAMILY);
MODULE_ALIAS_GENL_FAMILY(OVS_VPORT_FAMILY);
MODULE_ALIAS_GENL_FAMILY(OVS_FLOW_FAMILY);
MODULE_ALIAS_GENL_FAMILY(OVS_PACKET_FAMILY);
