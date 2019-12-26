#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <set>
#include <map>
#include <utility>
/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

struct RoutTableCmp {
  bool operator() (const RoutingTableEntry &a, const RoutingTableEntry &b) const {
    if (a.addr != b.addr) return a.addr < b.addr;
    return a.len < b.len;
  }
};

std::set<RoutingTableEntry, RoutTableCmp> rtSet;
std::map<std::pair<uint32_t, uint32_t>, RoutingTableEntry> rtMap; 

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  // TODO:
  if (insert) { 
    //printf("FUCKKKKKKKKKKKKKKK: %x\n", entry.addr);
    rtMap.emplace(std::make_pair(entry.addr, entry.len), entry);
  }
    else rtMap.erase(std::make_pair(entry.addr, entry.len));
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  *nexthop = 0;
  *if_index = 0;

  uint32_t  big = 0;

  RoutingTableEntry bigRT;

  for (std::map<std::pair<uint32_t, uint32_t>, RoutingTableEntry>::iterator it = rtMap.begin();  it != rtMap.end();  it++) {
      uint32_t  tmp = it->first.second == 32u ? 0xFFFFFFFFu : ((0x1u << it->first.second) - 0x1u); // big endian
      uint32_t t = ((tmp & addr) ^ (tmp & it->first.first));
      if (t == 0 && (it->first.second > big)) {
        big = it->first.second;
        bigRT = it->second;
      }
  }

  if (big > 0) {
    *nexthop = bigRT.nexthop;
    *if_index = bigRT.if_index;
    return true;
  }

  return false;
}
