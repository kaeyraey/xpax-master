#ifndef H_CHAINPARAMSSEEDS
#define H_CHAINPARAMSSEEDS
// List of fixed seed nodes for the bitcoin network
// AUTOGENERATED by contrib/devtools/generate-seeds.py

// Each line contains a 16-byte IPv6 address and a port.
// IPv4 as well as onion addresses are wrapped inside a IPv6 address accordingly.
static SeedSpec6 pnSeed6_main[] = {
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x4d,0x03,0xd9}, 15876},
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xd1,0xfa,0xe5,0x48}, 15876}
};

static SeedSpec6 pnSeed6_test[] = {

};

static const unsigned int pnSeed[] = {
0x2D4D03D9,
0xD1FAE548
};


static const unsigned int pnTestnetSeed[] = {

};
#endif
