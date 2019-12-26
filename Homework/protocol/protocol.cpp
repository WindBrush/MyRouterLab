#include "rip.h"
#include <stdint.h>
#include <stdlib.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) 
{
  // TODO:

  uint32_t  con_len = (packet[2] << 8) + (packet[2 + 1]);
  if (con_len > len) return false;

  uint16_t header_len = (packet[0]&0x0F) << 2; // length * 4;
  uint8_t UDP_HDR_len = 8;
  uint16_t  rip_len =  header_len + UDP_HDR_len;

  // if rip packet length > 25 entries, false;
  if (con_len - rip_len > RIP_MAX_ENTRY * 20) return false;

  uint16_t rip_com_len = rip_len;
  uint8_t command  = packet[rip_com_len];
  if (command != 1 && command != 2) return false;
  (*output).command = command;

  //check version
  uint16_t rip_ver_len = rip_com_len + 1;
  uint8_t version =  packet[rip_ver_len];
  if (version != 2) return false;

  //check zero
  uint16_t rip_zero_len = rip_ver_len + 1;
  uint16_t zero = (packet[rip_zero_len] << 8) + packet[rip_zero_len + 1];
  if (zero != 0) return false;

  RipEntry tmpEntry;
  uint16_t family = 0;
  uint16_t tag = 0;
  uint32_t metric = 0;

uint8_t rip_ip_family_len = 0,
                rip_ip_tag_len = 2,
                rip_ip_addr_len = 4,
                rip_ip_mask_len = 8,
                rip_ip_next_len = 12,
                rip_ip_metric_len = 16;
  
  (*output).numEntries = 0;
  for (uint16_t rip_ip_len  = rip_zero_len+2; rip_ip_len < len; rip_ip_len += 20)
  {
      int pos = 0;
      pos = rip_ip_len + rip_ip_family_len;
      family = (packet[pos] << 8) +  (packet[pos + 1]);
      if (!(family == 2 && command == 2) && !(family == 0 && command == 1)) return false; // check family

      pos = rip_ip_len +  rip_ip_tag_len;
      tag = (packet[pos] << 8) + (packet[pos + 1]);
      if (tag != 0) return false;

      pos = rip_ip_len + rip_ip_metric_len;
      for (int i = 0; i < 4; ++i) metric += (packet[pos+i] << ((3-i)*8));
      if (!(metric >= 1u && metric <= 16u)) return false;

      uint32_t tt = 0;
      for (int i = 0; i < 4; ++i) tt += (packet[pos+i] << (i*8));
      tmpEntry.metric = tt;

      tt = 0;
      pos = rip_ip_len + rip_ip_mask_len;
      for (int  i = 0; i < 4; ++i) tt += (packet[pos+i] << (i*8));
       tmpEntry.mask = tt;
      // tmpEntry.mask = (packet[pos])
      //      + (packet[pos + 1] << 8)
      //      + (packet[pos + 2] << 16)
      //      + (packet[pos + 3] << 24);

      for (int j = 0, flag = 0; j < 32; ++j){
      if (!flag){
        if (tmpEntry.mask & (1u << j)) continue;
            else
                flag = 1;
      } else{
        if (tmpEntry.mask & (1u << j)){
          return false;
        } else{
          continue;
        }
      }
    }

    tt = 0;
    pos = rip_ip_len + rip_ip_addr_len;
    for (int  i = 0; i < 4; ++i) tt += (packet[pos+i] << (i*8));
    tmpEntry.addr = tt;
    //  tmpEntry.addr = (packet[pos])
    //     + (packet[pos + 1] << 8)
    //     + (packet[pos + 2] << 16)
    //     + (packet[pos + 3] << 24);

    tt = 0;
    pos = rip_ip_len + rip_ip_next_len;
    for (int  i = 0; i < 4; ++i) tt += (packet[pos+i] << (i*8));
    tmpEntry.nexthop = tt;
      // tmpEntry.nexthop = (packet[pos])
      //   + (packet[pos + 1] << 8)
      //   + (packet[pos + 2] << 16)
      //   + (packet[pos + 3] << 24);

    (*output).entries[(*output).numEntries++] = tmpEntry;
  }

  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体dsadadasd
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) 
{
  // TODO:
  uint8_t rip_ip_family_len = 0,
                rip_ip_tag_len = 2,
                rip_ip_addr_len = 4,
                rip_ip_mask_len = 8,
                rip_ip_next_len = 12,
                rip_ip_metric_len = 16;

  uint8_t rip_ip_command_len = 0,
                  rip_ip_version_len = 1,
                  rip_ip_zero_len = 2;
  uint16_t rip_ip_len = rip_ip_zero_len+ 2;

  buffer[rip_ip_command_len] = rip->command;
  buffer[rip_ip_version_len] = 0x02;
  buffer[rip_ip_zero_len] = 0x00;
  buffer[rip_ip_zero_len + 1] = 0x00;

  for (int  i = 0;  i < rip->numEntries; ++i, rip_ip_len += 20)
  {
    int pos = rip_ip_len + rip_ip_family_len; //family
    buffer[pos] = 0x00;
    buffer[pos + 1] = rip->command == 2 ? 0x02 : 0x00;

   pos = rip_ip_len + rip_ip_tag_len;
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;

    pos = rip_ip_len + rip_ip_addr_len;
    for (int j = 0; j < 4; ++j) buffer[pos+j] = rip->entries[i].addr >> (j*8);
    // buffer[pos] = rip->entries[i].addr;
    // buffer[pos + 1] = rip->entries[i].addr >> 8;
    // buffer[pos + 2] = rip->entries[i].addr >> 16;
    // buffer[pos + 3] = rip->entries[i].addr >> 24;

    pos = rip_ip_len + rip_ip_mask_len;
    for (int j = 0; j < 4; ++j) buffer[pos+j] = rip->entries[i].mask >> (j*8);
    // buffer[pos] = rip->entries[i].mask;
    // buffer[pos + 1] = rip->entries[i].mask >> 8;
    // buffer[pos + 2] = rip->entries[i].mask >> 16;
    // buffer[pos + 3] = rip->entries[i].mask >> 24;

    pos = rip_ip_len + rip_ip_next_len;
    for (int j = 0; j < 4; ++j) buffer[pos+j] = rip->entries[i].nexthop >> (j*8);
    // buffer[pos] = rip->entries[i].nexthop;
    // buffer[pos + 1] = rip->entries[i].nexthop >> 8;
    // buffer[pos + 2] = rip->entries[i].nexthop >> 16;
    // buffer[pos + 3] = rip->entries[i].nexthop >> 24;

    pos = rip_ip_len + rip_ip_metric_len;
    for (int j = 0; j < 4; ++j) buffer[pos+j] = rip->entries[i].metric >> (j*8);
    // buffer[pos] = rip->entries[i].metric;
    // buffer[pos + 1] = rip->entries[i].metric >> 8;
    // buffer[pos + 2] = rip->entries[i].metric >> 16;
    // buffer[pos + 3] = rip->entries[i].metric >> 24;
  }

  return rip_ip_len;
}
