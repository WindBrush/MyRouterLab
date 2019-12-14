#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
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
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output)
{
  uint8_t fir_len = packet[0] & 0x0F;
  int head_len = fir_len * 4;
  uint32_t tot_len = (uint32_t)packet[3]+(uint32_t)(packet[2]<<8);

  if (tot_len > len) return false;

  if ( packet[head_len + 8] != 2 && packet[head_len + 8] != 1) return false;
  output->command = packet[head_len + 8];
  if (packet[head_len + 9] != 2) return false;

  if (packet[head_len + 10] != 0 || packet[head_len + 11] != 0) return false;

  int nums = (tot_len - 32) / 20;
  uint8_t token = packet[head_len + 8];
  int len_out = head_len + 12;

  for (int i = 0; i < nums; ++i)
  {
    if (token == 1 && (packet[len_out]!=0 || packet[len_out + 1]!=0)) return false;
    if (token == 2 && (packet[len_out]!=0 || packet[len_out + 1]!=2)) return false;
    
    for( int j = len_out + 8; j < len_out + 12; j ++){
      if(packet[j] != 0xFF && packet[j] != 0) return false;
  }
    
    if (packet[len_out + 16] != 0 || packet[len_out + 17] != 0 || packet[len_out + 18] != 0 || (packet[len_out + 19] == 0 || packet[len_out + 19] > 16))
      return false;
    len_out = len_out + 20;
  }
  output->numEntries = nums;
  output->command = token;


  uint32_t rip_addr = 0;
  uint32_t rip_mask = 0;
  uint32_t rip_nexthop = 0;
  uint32_t rip_metrics = 0;
  uint32_t rip_addr_family = 0;
  len_out = head_len + 12;
  for (int i = 0; i < nums;  ++i)
  {
    rip_addr_family = 0;
    rip_addr = 0;
    rip_mask = 0;
    rip_nexthop = 0;
    rip_metrics = 0;

    rip_addr += ((uint32_t)packet[len_out + 7]) << 24;
    rip_addr += ((uint32_t)packet[len_out + 6]) << 16;
    rip_addr += ((uint32_t)packet[len_out + 5]) << 8;
    rip_addr += ((uint32_t)packet[len_out + 4]);

    rip_mask += ((uint32_t)packet[len_out + 11]) << 24;
    rip_mask += ((uint32_t)packet[len_out + 10]) << 16;
    rip_mask += ((uint32_t)packet[len_out + 9]) << 8;
    rip_mask += ((uint32_t)packet[len_out + 8]);

    rip_nexthop += ((uint32_t)packet[len_out + 15]) << 24;
    rip_nexthop += ((uint32_t)packet[len_out + 14]) << 16;
    rip_nexthop += ((uint32_t)packet[len_out + 13]) << 8;
    rip_nexthop += ((uint32_t)packet[len_out + 12]);

    rip_metrics = ((uint32_t)packet[len_out + 19])<<24;

    rip_addr_family += ((uint32_t)packet[len_out + 0])<<8;
    rip_addr_family += ((uint32_t)packet[len_out + 1]);

    output->entries[i].addr = rip_addr;
    output->entries[i].mask = rip_mask;
    output->entries[i].nexthop = rip_nexthop;
    output->entries[i].metric = rip_metrics;
    output->entries[i].addr_family = rip_addr_family;

    len_out = len_out + 20;
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
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