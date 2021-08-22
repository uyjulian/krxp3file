#include "cxdec.h"

#include <windows.h>
#include <winnt.h>
#include <string.h>
#include <stdbool.h>

typedef struct cxdec_xcode_state_
{
	uint8_t* start_pointer;
	uint8_t* current_pointer;
	uint32_t space_size;
	uint32_t random_seed;
} cxdec_xcode_state;

static uint32_t xcode_random(cxdec_xcode_state *xcode)
{
	uint32_t seed = xcode->random_seed;
	xcode->random_seed = 1103515245 * seed + 12345;
	return xcode->random_seed ^ (seed << 16) ^ (seed >> 16);
}

static bool push_bytes_xcode(cxdec_xcode_state *xcode, const uint8_t* code, uint32_t size)
{
	if ((uint32_t)xcode->current_pointer - (uint32_t)xcode->start_pointer + size > xcode->space_size)
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

static bool xcode_building_first_stage(const cxdec_information *information, cxdec_xcode_state *xcode)
{
	uint8_t result = xcode_random(xcode) % 3;
	const uint8_t* order = information->xcode_building_first_stage_order;
	if (result == order[0])
	{
		// MOV ESI, encryption_control_block
		// MOV EAX, uint32_t PTR DS:[ESI+((xcode_random(xcode) & 0x3ff) << 2)]
		if (!push_xcode_1xuint8(xcode, 0xbe)
			|| !push_xcode_1xuint32(xcode, (uint32_t)(information->encryption_control_block))
			|| !push_xcode_2xuint8(xcode, 0x8b, 0x86)
			|| !push_xcode_1xuint32(xcode, (xcode_random(xcode) & 0x3ff) << 2))
			return false;
	}
	else if (result == order[1])
	{
		// MOV EAX, xcode_random(xcode)
		if (!push_xcode_1xuint8(xcode, 0xb8)
			|| !push_xcode_1xuint32(xcode, xcode_random(xcode)))
			return false;
	}
	else if (result == order[2])
	{
		// MOV EAX, EDI
		if (!push_xcode_2xuint8(xcode, 0x8b, 0xc7))
			return false;
	}
	return true;
}

static bool xcode_building_stage0(const cxdec_information *information, cxdec_xcode_state *xcode, int stage);
static bool xcode_building_stage1(const cxdec_information *information, cxdec_xcode_state *xcode, int stage);

static bool xcode_building_stage0(const cxdec_information *information, cxdec_xcode_state *xcode, int stage)
{
	if (stage == 1)
		return xcode_building_first_stage(information, xcode);

	if (xcode_random(xcode) & 1) {
		if (!xcode_building_stage1(information, xcode, stage - 1))
			return false;
	}
	else {
		if (!xcode_building_stage0(information, xcode, stage - 1))
			return false;
	}

	uint8_t result = xcode_random(xcode) & 7;
	const uint8_t* order = information->xcode_building_stage_0_order;
	if (result == order[0])
	{
		// NOT EAX
		if (!push_xcode_2xuint8(xcode, 0xf7, 0xd0))
			return false;
	}
	else if (result == order[1])
	{
		// NEG EAX
		if (!push_xcode_2xuint8(xcode, 0xf7, 0xd8))
			return false;
	}
	else if (result == order[2])
	{
		// INC EAX
		if (!push_xcode_1xuint8(xcode, 0x40))
			return false;
	}
	else if (result == order[3])
	{
		// DEC EAX
		if (!push_xcode_1xuint8(xcode, 0x48))
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
	}
	else if (result == order[5])
	{
		// XOR EAX, xcode_random(xcode)
		if (!push_xcode_1xuint8(xcode, 0x35)
			|| !push_xcode_1xuint32(xcode, xcode_random(xcode)))
			return false;
	}
	else if (result == order[6])
	{
		if (xcode_random(xcode) & 1) {
			// ADD EAX, xcode_random(xcode)
			if (!push_xcode_1xuint8(xcode, 0x05))
				return false;
		}
		else {
			// SUB EAX, xcode_random(xcode)
			if (!push_xcode_1xuint8(xcode, 0x2d))
				return false;
		}
		if (!push_xcode_1xuint32(xcode, xcode_random(xcode)))
			return false;
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
	}
	return true;
}

static bool xcode_building_stage1(const cxdec_information *information, cxdec_xcode_state *xcode, int stage)
{
	if (stage == 1)
		return xcode_building_first_stage(information, xcode);

	// PUSH EBX
	if (!push_xcode_1xuint8(xcode, 0x53))
		return false;

	if (xcode_random(xcode) & 1) {
		if (!xcode_building_stage1(information, xcode, stage - 1))
			return false;
	}
	else {
		if (!xcode_building_stage0(information, xcode, stage - 1))
			return false;
	}

	// MOV EBX, EAX
	if (!push_xcode_2xuint8(xcode, 0x89, 0xc3))
		return false;

	if (xcode_random(xcode) & 1) {
		if (!xcode_building_stage1(information, xcode, stage - 1))
			return false;
	}
	else {
		if (!xcode_building_stage0(information, xcode, stage - 1))
			return false;
	}

	uint8_t result = xcode_random(xcode) % 6;
	const uint8_t* order = information->xcode_building_stage_1_order;
	if (result == order[0])
	{
		// ADD EAX, EBX
		if (!push_xcode_2xuint8(xcode, 0x01, 0xd8))
			return false;
	}
	else if (result == order[1])
	{
		// SUB EAX, EBX
		if (!push_xcode_2xuint8(xcode, 0x29, 0xd8))
			return false;
	}
	else if (result == order[2])
	{
		// NEG EAX, ADD EAX, EBX
		if (!push_xcode_2xuint8(xcode, 0xf7, 0xd8)
			|| !push_xcode_2xuint8(xcode, 0x01, 0xd8))
			return false;
	}
	else if (result == order[3])
	{
		// IMUL EAX, EBX
		if (!push_xcode_3xuint8(xcode, 0x0f, 0xaf, 0xc3))
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
	}
	// POP EBX
	return push_xcode_1xuint8(xcode, 0x5b);
}


static bool xcode_building_start(const cxdec_information *information, cxdec_xcode_state *xcode, int stage)
{
	// PUSH EDI, PUSH ESI, PUSH EBX, PUSH ECX, PUSH EDX
	if (!push_xcode_5xuint8(xcode, 0x57, 0x56, 0x53, 0x51, 0x52))
		return false;

	// MOV EDI, uint32_t PTR SS:[ESP+18] (load parameter0)
	if (!push_xcode_4xuint8(xcode, 0x8b, 0x7c, 0x24, 0x18))
		return false;

	if (!xcode_building_stage1(information, xcode, stage))
		return false;

	// POP EDX, POP ECX, POP EBX, POP ESI, POP EDI
	if (!push_xcode_5xuint8(xcode, 0x5a, 0x59, 0x5b, 0x5e, 0x5f))
		return false;

	// RETN
	return push_xcode_1xuint8(xcode, 0xc3);
}

static bool xcode_building(const cxdec_information *information, uint32_t seed, void *start, uint32_t size)
{
	cxdec_xcode_state xcode;
	int stage;

	xcode.start_pointer = (uint8_t *)start;
	xcode.current_pointer = (uint8_t *)start;
	xcode.space_size = size;
	xcode.random_seed = seed;

	for (stage = 5; stage > 0; --stage)
	{
		if (xcode_building_start(information, &xcode, stage))
			break;
		xcode.current_pointer = (uint8_t *)start;
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
	state->xcode = (uint8_t *)VirtualAlloc(NULL, 128 * 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!state->xcode)
	{
		return 1;
	}

	for (int i = 0; i < 128; i += 1)
	{
		xcode_building(information, i, state->xcode + i * 128, 128);
		state->address_list[i] = state->xcode + i * 128;
	}
	FlushInstructionCache(GetCurrentProcess(), state->xcode, 128 * 128);

	return 0;
}

void cxdec_release(cxdec_state *state)
{
	if (state->xcode)
	{
		VirtualFree(state->xcode, 0, MEM_RELEASE);
		state->xcode = NULL;
	}
}

static void cxdec_execute_xcode(cxdec_state *state, const cxdec_information *information, uint32_t hash, uint32_t *ret1, uint32_t *ret2)
{
	uint32_t index = hash & 0x7f;
	hash >>= 7;

	if (!state->xcode)
	{
		cxdec_init(state, information);
	}

	*ret1 = (*(uint32_t (*)(uint32_t))state->address_list[index])(hash);
	*ret2 = (*(uint32_t (*)(uint32_t))state->address_list[index])(~hash);
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
