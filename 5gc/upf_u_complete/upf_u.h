

#include <rte_meter.h> // Include the header defining rte_meter_trtcm_params

#define NF_TAG "upf_u"
#define SRC_INTF_ACCESS 0
#define SRC_INTF_CORE 1
#define SRC_INTF_SGI_LAN 2
#define SRC_INTF_CP 3
#define SRC_INTF_NUM (SRC_INTF_CP + 1)
#define FIX_BUFFER
#define DEFAULT_TB_RATE 10         // (Mbps)
#define DEFAULT_TB_DEPTH 10000  // Max proceed length
#define DEFAULT_TB_TOKENS 10000
#define APP_FLOWS_MAX 256
#define IP_MASKED(BIGENDIINT, LEN) (BIGENDIINT & (0xFFFFFFFF << (32-LEN)))
#define MAX_UE 256 // Max number of UEs
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define SESSION_MAX_FLOW_RULE 5
#define IS_DYNAMIC 0
#define MAX_OF_BUFFER_PACKET_SIZE 30000

/* trTCM */
struct rte_meter_trtcm_params app_trtcm_params = {
	.cir = 125000,    // bytes per secs
	.pir = 625000,    // bytes per secs
	.cbs = 2048,
	.pbs = 2048
};

/* Flow Separation*/
struct flow_entry {
    uint32_t subnet;  // (Network & Mask_bits)
    int flow_idx;     // maps to trTCM flows table
    bool in_use;      // to track if the slot is occupied
}typedef flow_entry_t;

/* Token Bucket */
struct tb_config {
    uint64_t tb_rate;    // rate at which tokens are generated (in MBps)
    uint64_t tb_depth;   // depth of the token bucket (in bytes)
    uint64_t tb_tokens;  // number of the tokens in the bucket at any given time (in bytes)
    uint64_t last_cycle;
    uint64_t cur_cycles;
    uint16_t used;
};

struct ue_tb {
    uint32_t ue_ip;
    uint32_t ue_ambr;
    uint32_t ue_pdr[SESSION_MAX_FLOW_RULE];
    uint32_t ue_gbr[SESSION_MAX_FLOW_RULE];
    uint32_t ue_mbr[SESSION_MAX_FLOW_RULE];
    
    unsigned long qos_total_pkt_length;
    unsigned long nqos_total_pkt_length;
    struct tb_config ue_nqos_tb_params;
    struct tb_config ue_qos_tb_params[SESSION_MAX_FLOW_RULE];
};

struct index_Pair{
    int x_index;
    int y_index;
};
