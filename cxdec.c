#include "cxdec.h"

#include <windows.h>
#include <winnt.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#if 0
#define CXDEC_USE_CODEGEN
#endif

typedef struct cxdec_xcode_state_
{
	uint8_t* start_pointer;
	uint8_t* current_pointer;
	uint32_t space_size;
	uint32_t random_seed;
} cxdec_xcode_state;

// Gadgets
static void cxdec_gadget_mov_val(cxdec_gadget_context *context)
{
	context->reg1 = context->current_data;
}

static void cxdec_gadget_load_arg(cxdec_gadget_context *context)
{
	context->reg1 = context->arg;
}

static void cxdec_gadget_mov_reg(cxdec_gadget_context *context)
{
	context->reg2 = context->reg1;
}

static void cxdec_gadget_not(cxdec_gadget_context *context)
{
	context->reg1 ^= 0xFFFFFFFF;
}

static void cxdec_gadget_neg(cxdec_gadget_context *context)
{
	context->reg1 = (uint32_t)(-(int32_t)(context->reg1));
}

static void cxdec_gadget_inc(cxdec_gadget_context *context)
{
	context->reg1 += 1;
}

static void cxdec_gadget_dec(cxdec_gadget_context *context)
{
	context->reg1 -= 1;
}

static void cxdec_gadget_add_val(cxdec_gadget_context *context)
{
	context->reg1 += context->current_data;
}

static void cxdec_gadget_sub_val(cxdec_gadget_context *context)
{
	context->reg1 -= context->current_data;
}

static void cxdec_gadget_xor_val(cxdec_gadget_context *context)
{
	context->reg1 ^= context->current_data;
}

static void cxdec_gadget_add_reg(cxdec_gadget_context *context)
{
	context->reg1 += context->reg2;
}

static void cxdec_gadget_sub_reg(cxdec_gadget_context *context)
{
	context->reg1 -= context->reg2;
}

static void cxdec_gadget_push(cxdec_gadget_context *context)
{
	if (context->stack_depth > (sizeof(context->stack) / sizeof(context->stack[0])))
	{
		return;
	}
	context->stack[context->stack_depth] = context->reg2;
	context->stack_depth += 1;
}

static void cxdec_gadget_pop(cxdec_gadget_context *context)
{
	if (context->stack_depth == 0)
	{
		return;
	}
	context->stack_depth -= 1;
	context->reg2 = context->stack[context->stack_depth];
}

static void cxdec_gadget_shr_reg(cxdec_gadget_context *context)
{
	context->reg1 >>= (context->reg2 & 0xF);
}

static void cxdec_gadget_shl_reg(cxdec_gadget_context *context)
{
	context->reg1 <<= (context->reg2 & 0xF);
}

static void cxdec_gadget_imul_reg(cxdec_gadget_context *context)
{
	context->reg1 *= context->reg2;
}

static void cxdec_gadget_table_ecb(cxdec_gadget_context *context)
{
	uint32_t ecb_val = 0;
	memcpy(&ecb_val, &(context->state->information->encryption_control_block[(context->reg1 & 0x3ff) << 2]), sizeof(ecb_val));
	context->reg1 = ecb_val;
}

static void cxdec_gadget_interlace(cxdec_gadget_context *context)
{
	context->reg1 = ((context->reg1 & 0xAAAAAAAA) >> 1) | ((context->reg1 & 0x55555555) << 1);
}
// Gadgets end

static bool push_gadget_func(cxdec_gadget_state *gadget_state, cxdec_gadget_func gadget_func, uint32_t gadget_data)
{
	if (gadget_state->max_functions > (sizeof(gadget_state->gadget_functions) / sizeof(gadget_state->gadget_functions[0])))
		return false;
	gadget_state->gadget_functions[gadget_state->max_functions] = gadget_func;
	gadget_state->gadget_data[gadget_state->max_functions] = gadget_data;
	gadget_state->max_functions += 1;
	return true;
}

static uint32_t xcode_random(cxdec_xcode_state *xcode)
{
	uint32_t seed = xcode->random_seed;
	xcode->random_seed = 1103515245 * seed + 12345;
	return xcode->random_seed ^ (seed << 16) ^ (seed >> 16);
}

static bool push_bytes_xcode(cxdec_xcode_state *xcode, const uint8_t* code, uint32_t size)
{
	if ((uintptr_t)xcode->current_pointer - (uintptr_t)xcode->start_pointer + size > xcode->space_size)
		return false;

	memcpy(xcode->current_pointer, code, size);
	xcode->current_pointer += size;

	return true;
}

static bool push_xcode_1xuint8(cxdec_xcode_state *xcode, uint8_t code0)
{
	uint8_t code[1] = {code0};
	return push_bytes_xcode(xcode, code, sizeof(code));
}

static bool push_xcode_2xuint8(cxdec_xcode_state *xcode, uint8_t code0, uint8_t code1)
{
	uint8_t code[2] = {code0, code1};
	return push_bytes_xcode(xcode, code, sizeof(code));
}

static bool push_xcode_3xuint8(cxdec_xcode_state *xcode, uint8_t code0, uint8_t code1, uint8_t code2)
{
	uint8_t code[3] = {code0, code1, code2};
	return push_bytes_xcode(xcode, code, sizeof(code));
}

static bool push_xcode_4xuint8(cxdec_xcode_state *xcode, uint8_t code0, uint8_t code1, uint8_t code2, uint8_t code3)
{
	uint8_t code[4] = {code0, code1, code2, code3};
	return push_bytes_xcode(xcode, code, sizeof(code));
}

static bool push_xcode_5xuint8(cxdec_xcode_state *xcode, uint8_t code0, uint8_t code1, uint8_t code2, uint8_t code3, uint8_t code4)
{
	uint8_t code[5] = {code0, code1, code2, code3, code4};
	return push_bytes_xcode(xcode, code, sizeof(code));
}

static bool push_xcode_6xuint8(cxdec_xcode_state *xcode, uint8_t code0, uint8_t code1, uint8_t code2, uint8_t code3, uint8_t code4, uint8_t code5)
{
	uint8_t code[6] = {code0, code1, code2, code3, code4, code5};
	return push_bytes_xcode(xcode, code, sizeof(code));
}

static bool push_xcode_1xuint32(cxdec_xcode_state *xcode, uint32_t code0)
{
	uint8_t code[4] = {(uint8_t)(code0 & 0xff), (uint8_t)(code0 >> 8), (uint8_t)(code0 >> 16), (uint8_t)(code0 >> 24)};
	return push_bytes_xcode(xcode, code, sizeof(code));
}

static bool xcode_building_first_stage(const cxdec_information *information, cxdec_xcode_state *xcode, cxdec_gadget_state *gadget_state)
{
	uint8_t result = xcode_random(xcode) % 3;
	const uint8_t* order = information->xcode_building_first_stage_order;
	if (result == order[0])
	{
		// MOV ESI, encryption_control_block
		// MOV EAX, uint32_t PTR DS:[ESI+((xcode_random(xcode) & 0x3ff) << 2)]
		uint32_t rand_val = xcode_random(xcode);
		if (!push_xcode_1xuint8(xcode, 0xbe)
			|| !push_xcode_1xuint32(xcode, (uint32_t)(information->encryption_control_block))
			|| !push_xcode_2xuint8(xcode, 0x8b, 0x86)
			|| !push_xcode_1xuint32(xcode, (rand_val & 0x3ff) << 2))
			return false;
		uint32_t ecb_val = 0;
		memcpy(&ecb_val, &(information->encryption_control_block[(rand_val & 0x3ff) << 2]), sizeof(ecb_val));
		if (!push_gadget_func(gadget_state, cxdec_gadget_mov_val, ecb_val))
			return false;
	}
	else if (result == order[1])
	{
		// MOV EAX, xcode_random(xcode)
		uint32_t rand_val = xcode_random(xcode);
		if (!push_xcode_1xuint8(xcode, 0xb8)
			|| !push_xcode_1xuint32(xcode, rand_val))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_mov_val, rand_val))
			return false;
	}
	else if (result == order[2])
	{
		// MOV EAX, EDI
		if (!push_xcode_2xuint8(xcode, 0x8b, 0xc7))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_load_arg, 0))
			return false;
	}
	return true;
}

static bool xcode_building_stage0(const cxdec_information *information, cxdec_xcode_state *xcode, cxdec_gadget_state *gadget_state, int stage);
static bool xcode_building_stage1(const cxdec_information *information, cxdec_xcode_state *xcode, cxdec_gadget_state *gadget_state, int stage);

static bool xcode_building_stage0(const cxdec_information *information, cxdec_xcode_state *xcode, cxdec_gadget_state *gadget_state, int stage)
{
	if (stage == 1)
		return xcode_building_first_stage(information, xcode, gadget_state);

	if (xcode_random(xcode) & 1) {
		if (!xcode_building_stage1(information, xcode, gadget_state, stage - 1))
			return false;
	}
	else {
		if (!xcode_building_stage0(information, xcode, gadget_state, stage - 1))
			return false;
	}

	uint8_t result = xcode_random(xcode) & 7;
	const uint8_t* order = information->xcode_building_stage_0_order;
	if (result == order[0])
	{
		// NOT EAX
		if (!push_xcode_2xuint8(xcode, 0xf7, 0xd0))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_not, 0))
			return false;
	}
	else if (result == order[1])
	{
		// NEG EAX
		if (!push_xcode_2xuint8(xcode, 0xf7, 0xd8))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_neg, 0))
			return false;
	}
	else if (result == order[2])
	{
		// INC EAX
		if (!push_xcode_1xuint8(xcode, 0x40))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_inc, 0))
			return false;
	}
	else if (result == order[3])
	{
		// DEC EAX
		if (!push_xcode_1xuint8(xcode, 0x48))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_dec, 0))
			return false;
	}
	else if (result == order[4])
	{
		// PUSH EBX
		// MOV EBX, EAX
		// AND EBX, AAAAAAAA
		// AND EAX, 55555555
		// SHR EBX, 1
		// SHL EAX, 1
		// OR EAX, EBX
		// POP EBX
		if (!push_xcode_1xuint8(xcode, 0x53)
			|| !push_xcode_2xuint8(xcode, 0x89, 0xc3)
			|| !push_xcode_6xuint8(xcode, 0x81, 0xe3, 0xaa, 0xaa, 0xaa, 0xaa)
			|| !push_xcode_5xuint8(xcode, 0x25, 0x55, 0x55, 0x55, 0x55)
			|| !push_xcode_2xuint8(xcode, 0xd1, 0xeb)
			|| !push_xcode_2xuint8(xcode, 0xd1, 0xe0)
			|| !push_xcode_2xuint8(xcode, 0x09, 0xd8)
			|| !push_xcode_1xuint8(xcode, 0x5b))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_interlace, 0))
			return false;
	}
	else if (result == order[5])
	{
		// XOR EAX, xcode_random(xcode)
		uint32_t rand_val = xcode_random(xcode);
		if (!push_xcode_1xuint8(xcode, 0x35)
			|| !push_xcode_1xuint32(xcode, rand_val))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_xor_val, rand_val))
			return false;
	}
	else if (result == order[6])
	{
		bool should_add = (xcode_random(xcode) & 1) != 0;
		if (should_add) {
			// ADD EAX, xcode_random(xcode)
			if (!push_xcode_1xuint8(xcode, 0x05))
				return false;
		}
		else {
			// SUB EAX, xcode_random(xcode)
			if (!push_xcode_1xuint8(xcode, 0x2d))
				return false;
		}
		uint32_t rand_val = xcode_random(xcode);
		if (!push_xcode_1xuint32(xcode, rand_val))
			return false;
		if (should_add) {
			if (!push_gadget_func(gadget_state, cxdec_gadget_add_val, rand_val))
				return false;
		}
		else {
			if (!push_gadget_func(gadget_state, cxdec_gadget_sub_val, rand_val))
				return false;
		}
		
	}
	else if (result == order[7])
	{
		// MOV ESI, encryption_control_block
		// AND EAX, 3FFh
		// MOV EAX, uint32_t PTR DS:[ESI+EAX*4]
		if (!push_xcode_1xuint8(xcode, 0xbe)
			|| !push_xcode_1xuint32(xcode, (uint32_t)information->encryption_control_block)
			|| !push_xcode_1xuint8(xcode, 0x25)
			|| !push_xcode_1xuint32(xcode, 0x3ff)
			|| !push_xcode_3xuint8(xcode, 0x8b, 0x04, 0x86))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_table_ecb, 0))
			return false;
	}
	return true;
}

static bool xcode_building_stage1(const cxdec_information *information, cxdec_xcode_state *xcode, cxdec_gadget_state *gadget_state, int stage)
{
	if (stage == 1)
		return xcode_building_first_stage(information, xcode, gadget_state);

	// PUSH EBX
	if (!push_xcode_1xuint8(xcode, 0x53))
		return false;
	if (!push_gadget_func(gadget_state, cxdec_gadget_push, 0))
		return false;

	if (xcode_random(xcode) & 1) {
		if (!xcode_building_stage1(information, xcode, gadget_state, stage - 1))
			return false;
	}
	else {
		if (!xcode_building_stage0(information, xcode, gadget_state, stage - 1))
			return false;
	}

	// MOV EBX, EAX
	if (!push_xcode_2xuint8(xcode, 0x89, 0xc3))
		return false;
	if (!push_gadget_func(gadget_state, cxdec_gadget_mov_reg, 0))
		return false;

	if (xcode_random(xcode) & 1) {
		if (!xcode_building_stage1(information, xcode, gadget_state, stage - 1))
			return false;
	}
	else {
		if (!xcode_building_stage0(information, xcode, gadget_state, stage - 1))
			return false;
	}

	uint8_t result = xcode_random(xcode) % 6;
	const uint8_t* order = information->xcode_building_stage_1_order;
	if (result == order[0])
	{
		// ADD EAX, EBX
		if (!push_xcode_2xuint8(xcode, 0x01, 0xd8))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_add_reg, 0))
			return false;
	}
	else if (result == order[1])
	{
		// SUB EAX, EBX
		if (!push_xcode_2xuint8(xcode, 0x29, 0xd8))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_sub_reg, 0))
			return false;
	}
	else if (result == order[2])
	{
		// NEG EAX, ADD EAX, EBX
		if (!push_xcode_2xuint8(xcode, 0xf7, 0xd8)
			|| !push_xcode_2xuint8(xcode, 0x01, 0xd8))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_neg, 0))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_add_reg, 0))
			return false;
	}
	else if (result == order[3])
	{
		// IMUL EAX, EBX
		if (!push_xcode_3xuint8(xcode, 0x0f, 0xaf, 0xc3))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_imul_reg, 0))
			return false;
	}
	else if (result == order[4])
	{
		// PUSH ECX
		// MOV ECX, EBX
		// AND ECX, 0F
		// SHL EAX, CL
		// POP ECX
		if (!push_xcode_1xuint8(xcode, 0x51)
			|| !push_xcode_2xuint8(xcode, 0x89, 0xd9)
			|| !push_xcode_3xuint8(xcode, 0x83, 0xe1, 0x0f)
			|| !push_xcode_2xuint8(xcode, 0xd3, 0xe0)
			|| !push_xcode_1xuint8(xcode, 0x59))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_shl_reg, 0))
			return false;
	}
	else if (result == order[5])
	{
		// PUSH ECX
		// MOV ECX, EBX
		// AND ECX, 0F
		// SHR EAX, CL
		// POP ECX
		if (!push_xcode_1xuint8(xcode, 0x51)
			|| !push_xcode_2xuint8(xcode, 0x89, 0xd9)
			|| !push_xcode_3xuint8(xcode, 0x83, 0xe1, 0x0f)
			|| !push_xcode_2xuint8(xcode, 0xd3, 0xe8)
			|| !push_xcode_1xuint8(xcode, 0x59))
			return false;
		if (!push_gadget_func(gadget_state, cxdec_gadget_shr_reg, 0))
			return false;
	}
	// POP EBX
	if (!push_xcode_1xuint8(xcode, 0x5b))
		return false;
	if (!push_gadget_func(gadget_state, cxdec_gadget_pop, 0))
		return false;
	return true;
}


static bool xcode_building_start(const cxdec_information *information, cxdec_xcode_state *xcode, cxdec_gadget_state *gadget_state, int stage)
{
	// PUSH EDI, PUSH ESI, PUSH EBX, PUSH ECX, PUSH EDX
	if (!push_xcode_5xuint8(xcode, 0x57, 0x56, 0x53, 0x51, 0x52))
		return false;

	// MOV EDI, uint32_t PTR SS:[ESP+18] (load parameter0)
	if (!push_xcode_4xuint8(xcode, 0x8b, 0x7c, 0x24, 0x18))
		return false;

	if (!xcode_building_stage1(information, xcode, gadget_state, stage))
		return false;

	// POP EDX, POP ECX, POP EBX, POP ESI, POP EDI
	if (!push_xcode_5xuint8(xcode, 0x5a, 0x59, 0x5b, 0x5e, 0x5f))
		return false;

	// RETN
	return push_xcode_1xuint8(xcode, 0xc3);
}

static bool xcode_building(const cxdec_information *information, uint32_t seed, void *start, uint32_t size, cxdec_gadget_state *gadget_state)
{
	cxdec_xcode_state xcode;
	int stage;

	xcode.start_pointer = (uint8_t *)start;
	xcode.space_size = size;
	xcode.random_seed = seed;

	for (stage = 5; stage > 0; --stage)
	{
		xcode.current_pointer = (uint8_t *)start;

		memset(gadget_state->gadget_functions, 0, sizeof(gadget_state->gadget_functions));
		gadget_state->max_functions = 0;

		if (xcode_building_start(information, &xcode, gadget_state, stage))
			break;
	}
	if (!stage)
	{
		return false;
	}
	return true;
}

int cxdec_init(cxdec_state *state, const cxdec_information *information)
{
	if (state->xcode)
	{
		cxdec_release(state);
	}
#ifdef CXDEC_USE_CODEGEN
	state->xcode = (uint8_t *)VirtualAlloc(NULL, 128 * 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#else
	state->xcode = (uint8_t *)malloc(128 * 128);
#endif
	if (!state->xcode)
	{
		return 1;
	}
	state->information = information;

	for (int i = 0; i < 128; i += 1)
	{
		xcode_building(information, i, state->xcode + i * 128, 128, &state->gadget_list[i]);
		state->address_list[i] = (cxdec_generated_code_func)(state->xcode + i * 128);
	}
#ifdef CXDEC_USE_CODEGEN
	FlushInstructionCache(GetCurrentProcess(), state->xcode, 128 * 128);
#endif

	return 0;
}

void cxdec_release(cxdec_state *state)
{
	if (state->xcode)
	{
#ifdef CXDEC_USE_CODEGEN
		VirtualFree(state->xcode, 0, MEM_RELEASE);
#else
		free(state->xcode);
#endif
		state->xcode = NULL;
	}
}

static uint32_t cxdec_execute_xcode_single(cxdec_state *state, uint32_t index, uint32_t hash)
{
#ifdef CXDEC_USE_CODEGEN
	cxdec_gadget_context gadget_context;
	memset(&gadget_context, 0, sizeof(gadget_context));
	gadget_context.state = state;
	gadget_context.arg = hash;
	const cxdec_gadget_state *gadget_cur = &(state->gadget_list[index]);
	for (int i = 0; i < gadget_cur->max_functions; i += 1)
	{
		gadget_context.current_data = gadget_cur->gadget_data[i];
		gadget_cur->gadget_functions[i](&gadget_context);
	}
	return gadget_context.reg1;
#else
	return state->address_list[index](hash);
#endif
}

static void cxdec_execute_xcode(cxdec_state *state, const cxdec_information *information, uint32_t hash, uint32_t *ret1, uint32_t *ret2)
{
	uint32_t index = hash & 0x7f;
	hash >>= 7;

	if (!state->xcode)
	{
		cxdec_init(state, information);
	}

	*ret1 = cxdec_execute_xcode_single(state, index, hash);
	*ret2 = cxdec_execute_xcode_single(state, index, hash ^ 0xFFFFFFFF);
}

static void __cxdec_decode(cxdec_state *state, const cxdec_information *information, uint32_t hash, uint32_t offset, uint8_t *buf, uint32_t len)
{
	uint8_t key[12];
	uint32_t ret[2], i;

	cxdec_execute_xcode(state, information, hash, &ret[0], &ret[1]);

	key[8] = (uint8_t)(ret[0] >> 8);
	key[9] = (uint8_t)(ret[0] >> 16);
	key[10] = (uint8_t)(ret[0]);
	uint32_t key1 = ret[1] >> 16;
	uint32_t key2 = ret[1] & 0xffff;
	*(uint32_t *)&key[0] = key1;

	if (key1 == key2)
		++key2;

	*(uint32_t *)&key[4] = key2;

	if (!key[10])
		key[10] = 1;

	if ((key2 >= offset) && (key2 < offset + len))
		buf[key2 - offset] ^= key[9];

	if ((key1 >= offset) && (key1 < offset + len))
		buf[key1 - offset] ^= key[8];

	for (i = 0; i < len; ++i)
		buf[i] ^= key[10];
}

void cxdec_decode(cxdec_state *state, const cxdec_information *information, uint32_t hash, uint32_t offset, uint8_t *buf, uint32_t len)
{
	uint32_t boundary = (hash & information->boundary_mask) + information->boundary_offset;
	uint32_t dec_len = 0;

	if (offset < boundary) {
		if (offset + len > boundary)
			dec_len = boundary - offset;
		else
			dec_len = len;
		__cxdec_decode(state, information, hash, offset, buf, dec_len);
		offset += dec_len;
		buf += dec_len;
		dec_len = len - dec_len;
	}
	else
		dec_len = len;

	if (dec_len)
		__cxdec_decode(state, information, (hash >> 16) ^ hash, offset, buf, dec_len);
}
