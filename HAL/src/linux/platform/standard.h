#include "router_hal.h"

// configure this to match the output of `ip a`
const char *interfaces[N_IFACE_ON_BOARD] = {
    "veth-r2-r1",
    "veth-r2-r3",
    "eth3",
    "eth4",
};
