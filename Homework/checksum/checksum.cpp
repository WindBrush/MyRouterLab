#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:

  uint16_t header_len = (packet[0] & 0x0F) << 2; //  length * 4 bytes
  uint32_t cksum = 0;
  uint32_t ofl  = 0;
  for (int i = 0; i < header_len/2; ++i)  cksum += (packet[i<<1] << 8) + packet[(i<<1)+1]; // high 16 add low 16

  while (cksum > 0xFFFF)
  {
    // ofl = (cksum & 0xFFFF0000) >> 16;   // high 16 add low 16
    // cksum &= 0xFFFF;
    // cksum += ofl;
    cksum  = (cksum >> 16) + (cksum & 0xFFFF);
    cksum += (cksum >> 16);
  }

  return uint16_t(~cksum) == 0;
}

uint16_t getIPChecksum(uint8_t *packet, size_t len)
{
  /*To Do: might  not use this*/
}
