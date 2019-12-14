#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) 
{
	// TODO:

	uint8_t TTL = 8,  CKS = 10;

	uint32_t cksum = 0;
	//uint32_t ofl = 0;
	uint16_t header_len = (packet[0] & 0x0F) << 2; // length * 4

	// check
	for (int i = 0; i < header_len/2; ++i)  cksum += (packet[i<<1] << 8) + packet[(i<<1)+1]; // high 16 add low 16

	while (cksum > 0xFFFF)
	{
		cksum  = (cksum >> 16) + (cksum & 0xFFFF); // high 16  add low 16
		cksum += (cksum >> 16);
	}

	//foward

	if (uint16_t(~cksum) == 0) { 
		packet[TTL] -= 1; // update TTL

		packet[CKS] = 0x0;
		packet[CKS + 1] = 0x0;

		//get new checksum
		cksum = 0; 
		for (int i = 0; i < header_len/2; ++i)  cksum += (packet[i<<1] << 8) + packet[(i<<1)+1]; // high 16 add low 16

		while (cksum > 0xFFFF)
		{
			cksum  = (cksum >> 16) + (cksum & 0xFFFF); // high 16  add low 16
			cksum += (cksum >> 16);
		}
		uint16_t tmp = uint16_t(~cksum);
   	 	packet[CKS] = (tmp & 0xFF00) >> 8;
   		packet[CKS + 1] = tmp & 0x00FF;
    	return true;
	}
	return false;
}
