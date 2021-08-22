
#ifndef __CXDEC_H__
#define __CXDEC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct cxdec_information_
{
	uint8_t xcode_building_first_stage_order[3];
	uint8_t xcode_building_stage_0_order[8];
	uint8_t xcode_building_stage_1_order[6];
	uint16_t boundary_mask;
	uint16_t boundary_offset;
	uint8_t encryption_control_block[4096];
} cxdec_information;

typedef struct cxdec_state_
{
	uint8_t *xcode;				// Holds 128 decryption functions, each function is 100 bytes
	void *address_list[128];	// Addresses of 128 decryption functions (indexed by index)
} cxdec_state;

extern void cxdec_release(cxdec_state *state);
extern int cxdec_init(cxdec_state *state, const cxdec_information *information);
extern void cxdec_decode(cxdec_state *state, const cxdec_information *information, uint32_t hash, uint32_t offset, uint8_t *buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
