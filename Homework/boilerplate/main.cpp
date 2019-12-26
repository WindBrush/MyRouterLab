#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utility>
#include <map>

#define BROADCAST_ADDR 0x090000e0 // 168.0.0.9

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

//extern uint16_t getIPChecksum(uint8_t *packet, size_t len);

extern std::map<std::pair<uint32_t, uint32_t>, RoutingTableEntry> rtMap; 

uint32_t converEndian(uint32_t val) {
  return ( (val & 0x000000FF) << 24) | ((val & 0x0000FF00) << 8) | ((val & 0x00FF0000) >> 8) | ((val & 0xFF000000) >> 24);
}

uint32_t lenToMask(uint32_t len) {
  return (len == 32) ? 0xFFFFFFFF : ((1<<len) - 1);
}

uint32_t checkIpAddr(uint32_t len, uint32_t addre) {
  return lenToMask(len) & addre;
}

void printRouterTable()
{
 //printf("This is the router to be print\n");
  printf("/*================================ Routing Table  ====================================*/\n");
  for (std::map<std::pair<uint32_t, uint32_t>, RoutingTableEntry>::iterator it = rtMap.begin();  it != rtMap.end();  it++) 
  {
     RoutingTableEntry tmp  = it->second;
     //printf("addr: %x , len: %u , if_index: %u , nexthop: %x , metric: %u\n", tmp.addr, tmp.len, tmp.if_index, tmp.nexthop, converEndian(tmp.metric));
    printf("----------------------------------------------\n");
     //printf("addr : %x \n", tmp.addr);
     printf("IPV4 addr:  %u.%u.%u.%u/%u\n",(uint8_t)(tmp.addr),(uint8_t)(tmp. addr >> 8),  (uint8_t)(tmp.addr >> 16), (uint8_t)(tmp.addr >> 24), tmp.len);
     printf("if_index:  %u\n",tmp.if_index);
     printf("nexthop:  %u.%u.%u.%u\n", (uint8_t)(tmp.nexthop), (uint8_t)(tmp.nexthop >> 8), (uint8_t)(tmp.nexthop >> 16), (uint8_t)(tmp.nexthop >> 24));
     printf("metric:  %u\n",converEndian(tmp.metric));
    printf("-----------------------------------------------\n");
  }
  printf("/*=================================================================================*/\n");
}

uint8_t packet[2048];
uint8_t output[2048];
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};

  /**
   * 代码中在发送 RIP 包的时候，会涉及到 IP 头的构造，由于不需要用各种高级特性，
   * 可以这么设定：V=4，IHL=5，TOS(DSCP/ECN)=0，ID=0，FLAGS/OFF=0，
   * TTL=1，其余按照要求实现即可。
   */
uint32_t initUdpHeader()
{
  output[0] = 0x45;
  output[1] = 0x00;
  // 2,3: len
  output[4] = 0;
  output[5] = 0;
  output[6] = 0;
  output[7] = 0;
  output[8] = 0x01; // TTL
  output[9] = 0x11; // Protocol: UDP
  // 10, 11 : checksum
  // 12: src ip. 16 dst ip
  output[16] = 0xe0;
  output[17] = 0x00;
  output[18] = 0x00;
  output[19] = 0x09;
  // UDP
  //  port = 520
  output[20] = 0x02;
  output[21] = 0x08;
  output[22] = 0x02;
  output[23] = 0x08;
  output[26] = 0x00;
  output[27] = 0x00;
}

uint32_t calculateCheckSum()
{
  uint32_t cksum = 0;
  for (int i = 0; i < 20; i += 2) {
    cksum += (((uint32_t)output[i] ) << 8);
    cksum += ((uint32_t)output[i + 1]);
  }

  cksum -= (((uint32_t)output[10] ) << 8);
  cksum -= ((uint32_t)output[11]);
  while ((cksum >> 16) != 0) cksum = (cksum >> 16) + (cksum & 0xFFFF);
  return 0xFFFF - cksum; //to do
}

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0xFFFFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
         .metric = converEndian(1u)
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    // when testing, you can change 30s to 5s
    if (time > last_time + 30 * 1000) {
      // TODO: send complete routing table to every interface
      // ref. RFC2453 Section 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      printf("Timer\n");
      printRouterTable();
      initUdpHeader();
        for (uint32_t i  = 0; i < N_IFACE_ON_BOARD; ++i) // broadcast at every port
      {
        RipPacket*  sendPkt = new RipPacket();
        sendPkt -> command = 2; // response;
        sendPkt -> numEntries = 0;

        for (std::map<std::pair<uint32_t, uint32_t>, RoutingTableEntry>::iterator it = rtMap.begin();  it != rtMap.end();  it++)
        {
            RoutingTableEntry e = it -> second;
            if (e.if_index == i) continue; // IMPORTANT
            uint32_t mask_len = lenToMask(e.len);
            sendPkt -> entries[sendPkt->numEntries].addr = e.addr & mask_len;
            sendPkt -> entries[sendPkt->numEntries].mask = mask_len;
            sendPkt -> entries[sendPkt->numEntries].nexthop = e.nexthop;
            sendPkt -> entries[sendPkt->numEntries].metric = e.metric;
            sendPkt -> numEntries ++;
        } // end for rtMap
          uint32_t rip_len = assemble(sendPkt, &output[20+8]);
          uint32_t Udp_len = sendPkt -> numEntries * 20 + 8 + 4;
          uint32_t output_len = sendPkt -> numEntries * 20 + 20 + 8 + 4;
          output[2] = (uint8_t)((output_len>>8) & 0xFF);
          output[3] = (uint8_t)((output_len) & 0xFF);

          output[12] = (uint8_t)((addrs[i]) & 0xFF);
          output[13] = (uint8_t)((addrs[i] >> 8) & 0xFF);
          output[14] = (uint8_t)((addrs[i] >> 16) & 0xFF);
          output[15] = (uint8_t)((addrs[i] >> 24) & 0xFF);
          
          output[24] = (uint8_t)((Udp_len >> 8) & 0xFF);
          output[25] = (uint8_t)((Udp_len) & 0xFF);

          uint32_t cksum = calculateCheckSum();
          output[10] = (uint8_t)((cksum >> 8) & 0xFF);
          output[11] = (uint8_t)((cksum) & 0xFF);

          macaddr_t tmpMac;
          if (HAL_ArpGetMacAddress(i, BROADCAST_ADDR, tmpMac) == 0) {
            HAL_SendIPPacket(i, output, rip_len +  20 + 8, tmpMac);
          } 
          else printf("Error: Dest_Mac is not found!");
      } // end for N_IFACE
      printf("30s Timer\n");
      // TODO: print complete routing table to stdout/stderr
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      printf("HAL_ERR_EOF\n");
      break;
    } else if (res < 0) {
      printf("RES < 0\n");
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // TODO: extract src_addr and dst_addr from packet (big endian)
    src_addr = 0;
    for (int i = 15; i >= 13; --i) {
      src_addr += packet[i]; 
      src_addr <<= 8;
    }
    src_addr += packet[12];

    dst_addr = 0;
    for (int i = 19; i >= 17; --i) {
      dst_addr += packet[i]; 
      dst_addr <<= 8;
    }
    dst_addr += packet[16];

    // 2. check whether dst is me
    printf("Received Address: SRC: %x   DST:  %x\n",src_addr, dst_addr);

    in_addr_t group_addr = BROADCAST_ADDR;
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
       if (memcmp(&dst_addr, &group_addr, sizeof(in_addr_t)) == 0) {
         //printf("IS ME!!!\n");
        dst_is_me = true;
        break;
      }
    }
    // TODO: handle rip multicast address(224.0.0.9)

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      
      if (disassemble(packet, res, &rip)) {
        //printf("WTFFFFFFFFFFFFFFFFFFFFFFFFFF: %u\n", rip.command);
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 Section 3.9.1
          // only need to respond to whole table requests in the lab
          if(rip.numEntries != 1 || converEndian(rip.entries[0].metric)!= 16 ){
            printf("ERROR!  in num or metrics\n");
            continue;//IMPORTANT
          }

          RipPacket resp;
          // TODO: fill resp
          resp.command = 2; resp.numEntries = 0;
           for (std::map<std::pair<uint32_t, uint32_t>, RoutingTableEntry>::iterator it = rtMap.begin();  it != rtMap.end();  it++)
           {
            RoutingTableEntry e = it -> second;
            uint32_t mask_len = lenToMask(e.len);
            if ( (checkIpAddr(e.len, e.addr) != (mask_len & src_addr)) && (e.if_index != if_index))
            {
              resp.entries[resp.numEntries].addr = e.addr & mask_len;
              resp.entries[resp.numEntries].mask = mask_len;
              resp.entries[resp.numEntries].nexthop = e.nexthop;
              resp.entries[resp.numEntries].metric = e.metric;
              resp.numEntries ++;
            }
           } // end for rtMap

            printRouterTable();

            
          // TODO: fill IP headers
          initUdpHeader();
            //src_dir dst_dir
          output[12] = (uint8_t)(addrs[if_index] & 0xFF);
          output[13] = (uint8_t)( (addrs[if_index] >>8) & 0xFF);
          output[14] = (uint8_t)( (addrs[if_index] >>16) & 0xFF);
          output[15] =  (uint8_t)( (addrs[if_index] >>24) & 0xFF);
          output[16] = (uint8_t)(src_addr & 0xFF);
          output[17] = (uint8_t)( (src_addr >>8) & 0xFF);
          output[18] = (uint8_t)( (src_addr >>16) & 0xFF);
          output[19] =  (uint8_t)( (src_addr >>24) & 0xFF);

          // TODO: fill UDP headers
          // port = 520
          output[20] = 0x02;
          output[21] = 0x08;
          output[22] = 0x02;
          output[23] = 0x08;

          // assembleRIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          uint32_t Udp_len  = resp.numEntries * 20 + 4 + 8;
          uint32_t output_len = resp.numEntries * 20 + 20 + 4 + 8;
          output[2] = (uint8_t)((output_len>>8) & 0xFF);
          output[3] =(uint8_t)(output_len & 0xFF);
          output[24] = (uint8_t)( (Udp_len  >> 8) & 0xFF);
          output[25] = (uint8_t)(Udp_len & 0xFF);

          // TODO: checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          uint32_t cksum = calculateCheckSum();//After first 20 generated, CHECKED
          output[10] = (uint8_t)((cksum >> 8) & 0xFF);
          output[11] = (uint8_t)(cksum & 0xFF);

          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 Section 3.9.2
          // TODO: update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // HINT: handle nexthop = 0 case
          // HINT: what is missing from RoutingTableEntry?
          // you might want to use `query` and `update` but beware of the difference between exact match and longest prefix match
          // optional: triggered updates? ref. RFC2453 3.10.1
          //printf("FOR UPDATE\n");
           RipPacket resp;
          bool flag = false; // if update
          resp.command = 2; resp.numEntries = 0;
           for (uint32_t i = 0; i < rip.numEntries; ++i)
          {
            uint32_t curMetric = rip.entries[i].metric;
			      uint32_t curAddr = rip.entries[i].addr;
			      uint32_t curMask = rip.entries[i].mask;
			      uint32_t curLen = __builtin_popcount(curMask);
			      uint32_t curNexthop = rip.entries[i].nexthop;
            if (curNexthop == 0) curNexthop = src_addr;
            curMetric = converEndian(curMetric);
            curMetric = std::min(curMetric + 1, 16u);
           // printf("Metricccccccccccccccccccccccccccc:        %u\n",curMetric);
            bool isfound = false;
            for (std::map<std::pair<uint32_t, uint32_t>, RoutingTableEntry>::iterator it = rtMap.begin();  it != rtMap.end();  it++)
            {
              RoutingTableEntry  e = it -> second;
              if (curLen == e.len)
              {
                if (checkIpAddr(e.len, e.addr) == (lenToMask(curLen) & curAddr) ) 
                {
                  isfound = true;
                  //printf("Diff thop: %x %x\n",curNexthop, e.nexthop);
                  if (curMetric >= 16 && curNexthop == e.nexthop) { // Del
                  //printf("DELLLLLLLLLLLLLLLLLLLLLLLLLLL\n");
                    RoutingTableEntry tmpDel;
                    tmpDel.addr = curAddr;
                    tmpDel.len = curLen;
                    update(false, tmpDel);
                    break;
                  }

                  if (curMetric <= converEndian(e.metric))
                  {
                    flag = true;
                    it->second.addr = curAddr;
                    it->second.metric = converEndian(curMetric);
                    it->second.nexthop = curNexthop;
                    it->second.if_index = if_index;
                  }
                  break;
                }
              } // end if curLen == e.len
            } // end for rtMap
            if (!isfound && curMetric < 16)
            {
              flag = true;
              RoutingTableEntry tmpUp;
              tmpUp.addr = curAddr;
              tmpUp.len = curLen;
              tmpUp.metric = converEndian(curMetric);
              tmpUp.if_index = if_index;
              tmpUp.nexthop = curNexthop;
              update(true, tmpUp);
            }
          } // end for rip.numEntries

          printRouterTable();

          if (flag)
          {
            printf("RoutingTable Updated.\n");
            output[0] = 0x45;
            output[1] = 0x00;
            output[4] = 0x00;
            output[5] = 0x00;
            output[6] = 0x00;
            output[7] = 0x00;
            output[8] = 0x01;
            output[9] = 0x11;
            output[16] = 0xe0;
            output[17] = 0x00;
            output[18] = 0x00;
            output[19] = 0x09;
            output[20] = 0x02;
            output[21] = 0x08;
            output[22] = 0x02;
            output[23] = 0x08;
            output[26] = 0;
            output[27] = 0;
            for (uint32_t i = 0; i < N_IFACE_ON_BOARD; ++i)
            {
              RipPacket sendPkt;
              sendPkt.command = 2; sendPkt.numEntries = 0;
              for (std::map<std::pair<uint32_t, uint32_t>, RoutingTableEntry>::iterator it = rtMap.begin();  it != rtMap.end();  it++)
              {
                  RoutingTableEntry e = it->second;
                  uint32_t mask_len  = lenToMask(e.len);
                  if (e.if_index != i) {
                    sendPkt.entries[sendPkt.numEntries].addr = e.addr & mask_len;
                    sendPkt.entries[sendPkt.numEntries].mask = mask_len;
                    sendPkt.entries[sendPkt.numEntries].metric = e.metric;
                    sendPkt.entries[sendPkt.numEntries].nexthop = e.nexthop;
                   // printf("nexthop %x\n",e.nexthop);
                    sendPkt.numEntries ++;
                  }
              } // end for rtMap
                uint32_t rip_len = assemble(&sendPkt, &output[20 + 8]);
                uint32_t Udp_len = 4 + 8 + sendPkt.numEntries * 20;
                uint32_t output_len = 20 + 4 + 8 + sendPkt.numEntries * 20;
                output[24] = (uint8_t)( (Udp_len >> 8) & 0xFF);
                output[25] = (uint8_t)(Udp_len&0xFF);
                output[2] = (uint8_t)((output_len>>8) & 0xFF);
                output[3] =(uint8_t)(output_len & 0xFF);
                output[12] = (uint8_t)(addrs[i] & 0xFF);//src_dir和dst_dir
                output[13] = (uint8_t)( (addrs[i] >>8) & 0xFF);
                output[14] = (uint8_t)( (addrs[i] >>16) & 0xFF);
                output[15] =  (uint8_t)( (addrs[i] >>24) & 0xFF);
                uint32_t cksum = calculateCheckSum();//After first 20 generated, CHECKED
                output[10] = (uint8_t)((cksum >> 8) & 0xFF);
                output[11] = (uint8_t)(cksum & 0xFF);
                macaddr_t group_mac;
                if (HAL_ArpGetMacAddress(i, BROADCAST_ADDR, group_mac) == 0)
                {
                  HAL_SendIPPacket(i, output, rip_len + 20 + 8, group_mac);
                  //printf("update response!!!\n");
                }
                else
                  printf("WRONG! DST_MAC NOT FOUND!");
            } // end for N_IFACE_ON_BOARD
          } // end if flag
            printRouterTable();
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t tnexthop, dest_if, tmpMetric;
      if (query(dst_addr, &tnexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (tnexthop == 0) { // zhi lian
          tnexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, tnexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          if (!validateIPChecksum(packet, res)) {
              printf("Invalid IP Checksum\n");
              continue;
          }
          if (!validateIPChecksum(output, res)) {
              printf("Invalid IP Checksum of output\n");
              continue;
          }
          // update ttl and checksum
         bool succ =  forward(output, res);
         if (!succ) {
            printf("Forward Error!");
         } else {
          // TODO(optional): check ttl=0 case
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
          }
        } else {
          // not found
          // you can drop it
          printf("ARP not found for nexthop %x\n", tnexthop);
        }
      } else {
        // not found
        // TODO(optional): send ICMP Host Unreachable
        printf("IP not found for src %x dst %x\n", src_addr, dst_addr);
      }
    }
  }
  return 0;
}

