#include <stdint.h>

/**
 *		Bits
 * Octets	8	7	6	5	4	3	2	1
 * 1		          Version	PT	(*)	E	S	PN
 * 2		Message Type
 * 3		Length (1st Octet)
 * 4		Length (2nd Octet)
 * 5		Tunnel Endpoint Identifier (1st Octet)
 * 6		Tunnel Endpoint Identifier (2nd Octet)
 * 7		Tunnel Endpoint Identifier (3rd Octet)
 * 8		Tunnel Endpoint Identifier (4th Octet)
 * 9		Sequence Number (1st Octet)1) 4)
 * 10		Sequence Number (2nd Octet)1) 4)
 * 11		N-PDU Number2) 4)
 * 12		Next Extension Header Type3) 4)
**/
typedef struct
{
  uint8_t ver_flags;
  uint8_t type;
  uint16_t length;			/* length in octets of the payload */
  uint32_t teid;
  uint16_t sequence;
  uint8_t pdu_number;
  uint8_t next_ext_type;
} gtpu_header_t;

#define OUTER_HEADER_REMOVAL_GTP_IP4   0
#define OUTER_HEADER_REMOVAL_GTP_IP6   1
#define OUTER_HEADER_REMOVAL_UDP_IP4   2
#define OUTER_HEADER_REMOVAL_UDP_IP6   3
#define OUTER_HEADER_REMOVAL_IP4       4
#define OUTER_HEADER_REMOVAL_IP6       5
#define OUTER_HEADER_REMOVAL_GTP       6
#define OUTER_HEADER_REMOVAL_S_TAG     7
#define OUTER_HEADER_REMOVAL_S_C_TAG   8
/* Packet Detection Rules */
typedef struct
{
  uint32_t id;
  uint16_t precedence;
#if 0
  upf_pdi_t pdi;
#endif
  uint8_t outer_header_removal;

  uint16_t far_id;
  uint16_t *urr_ids;
  uint32_t *qer_ids;
} upf_pdr_t;


/* Forward Action Rules - Forwarding Parameters */
typedef struct
{
  uint16_t flags;
#define FAR_F_REDIRECT_INFORMATION	BIT(0)
#define FAR_F_OUTER_HEADER_CREATION	BIT(1)

#if 0
  pfcp_destination_interface_t dst_intf;
  u32 dst_sw_if_index;
  u32 nwi_index;

  pfcp_redirect_information_t redirect_information;
  pfcp_outer_header_creation_t outer_header_creation;

  u32 peer_idx;
  u8 *rewrite;
#endif
} upf_far_forward_t;

/* Forward Action Rules */
typedef struct
{
  uint16_t id;
  uint16_t apply_action;
#define FAR_DROP       0x0001
#define FAR_FORWARD    0x0002
#define FAR_BUFFER     0x0004
#define FAR_NOTIFY_CP  0x0008
#define FAR_DUPLICATE  0x0010

  union
  {
    upf_far_forward_t forward;
    uint16_t bar_id;
  };
} upf_far_t;
