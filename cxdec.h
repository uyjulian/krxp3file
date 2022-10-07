
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

typedef struct cxdec_gadget_context_
{
	uint32_t current_data;
	uint32_t arg;
	uint32_t reg1;
	uint32_t reg2;
	uint32_t stack[128];
	uint32_t stack_depth;
	struct cxdec_state_ *state;
} cxdec_gadget_context;

typedef void (*cxdec_gadget_func)(cxdec_gadget_context *context);

typedef struct cxdec_gadget_state_
{
	cxdec_gadget_func gadget_functions[128]; // The list of functions to iterate through.
	uint32_t gadget_data[128];               // The RNG result needed for the function.
	uint32_t max_functions;                  // Maximum functions used.
} cxdec_gadget_state;

typedef uint32_t (*cxdec_generated_code_func)(uint32_t arg);

typedef struct cxdec_state_
{
	uint8_t *xcode;				          // Holds 128 decryption functions, each function is 100 bytes
	const cxdec_information *information; // Holds information
	cxdec_generated_code_func address_list[128];	          // Addresses of 128 decryption functions (indexed by index)
	cxdec_gadget_state gadget_list[128];  // Jump list of 128 decryption functions (for when code generation is not used)
} cxdec_state;

extern void cxdec_release(cxdec_state *state);
extern int cxdec_init(cxdec_state *state, const cxdec_information *information);
extern void cxdec_decode(cxdec_state *state, const cxdec_information *information, uint32_t hash, uint32_t offset, uint8_t *buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
