#include <stdio.h>
#include <string.h>

#define min(a, b)   ((a < b) ? a : b)

typedef unsigned char state_t[4][4];
typedef unsigned char row_t[4];

unsigned char Rcon[] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 
	0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 
	0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 
	0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 
	0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 
	0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 
	0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 
	0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 
	0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 
	0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 
	0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 
	0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 
	0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 
	0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 
	0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 
	0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 
	0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
};

unsigned char Sbox[] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

unsigned char InvSbox[] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 
	0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 
	0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 
	0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 
	0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 
	0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 
	0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 
	0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 
	0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 
	0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 
	0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 
	0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 
	0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 
	0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 
	0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 
	0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 
	0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

unsigned char GFMul2[] = {
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 
	0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 
	0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 
	0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 
	0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e, 
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 
	0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 
	0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 
	0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe, 
	0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 
	0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde, 
	0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 
	0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, 
	0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 
	0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05, 
	0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 
	0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25, 
	0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 
	0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45, 
	0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 
	0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65, 
	0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 
	0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85, 
	0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 
	0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5, 
	0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 
	0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5, 
	0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 
	0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
};

unsigned char GFMul4[] = {
	0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 
	0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c, 
	0x40, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x58, 0x5c, 
	0x60, 0x64, 0x68, 0x6c, 0x70, 0x74, 0x78, 0x7c, 
	0x80, 0x84, 0x88, 0x8c, 0x90, 0x94, 0x98, 0x9c, 
	0xa0, 0xa4, 0xa8, 0xac, 0xb0, 0xb4, 0xb8, 0xbc, 
	0xc0, 0xc4, 0xc8, 0xcc, 0xd0, 0xd4, 0xd8, 0xdc, 
	0xe0, 0xe4, 0xe8, 0xec, 0xf0, 0xf4, 0xf8, 0xfc, 
	0x1b, 0x1f, 0x13, 0x17, 0x0b, 0x0f, 0x03, 0x07, 
	0x3b, 0x3f, 0x33, 0x37, 0x2b, 0x2f, 0x23, 0x27, 
	0x5b, 0x5f, 0x53, 0x57, 0x4b, 0x4f, 0x43, 0x47, 
	0x7b, 0x7f, 0x73, 0x77, 0x6b, 0x6f, 0x63, 0x67, 
	0x9b, 0x9f, 0x93, 0x97, 0x8b, 0x8f, 0x83, 0x87, 
	0xbb, 0xbf, 0xb3, 0xb7, 0xab, 0xaf, 0xa3, 0xa7, 
	0xdb, 0xdf, 0xd3, 0xd7, 0xcb, 0xcf, 0xc3, 0xc7, 
	0xfb, 0xff, 0xf3, 0xf7, 0xeb, 0xef, 0xe3, 0xe7, 
	0x36, 0x32, 0x3e, 0x3a, 0x26, 0x22, 0x2e, 0x2a, 
	0x16, 0x12, 0x1e, 0x1a, 0x06, 0x02, 0x0e, 0x0a, 
	0x76, 0x72, 0x7e, 0x7a, 0x66, 0x62, 0x6e, 0x6a, 
	0x56, 0x52, 0x5e, 0x5a, 0x46, 0x42, 0x4e, 0x4a, 
	0xb6, 0xb2, 0xbe, 0xba, 0xa6, 0xa2, 0xae, 0xaa, 
	0x96, 0x92, 0x9e, 0x9a, 0x86, 0x82, 0x8e, 0x8a, 
	0xf6, 0xf2, 0xfe, 0xfa, 0xe6, 0xe2, 0xee, 0xea, 
	0xd6, 0xd2, 0xde, 0xda, 0xc6, 0xc2, 0xce, 0xca, 
	0x2d, 0x29, 0x25, 0x21, 0x3d, 0x39, 0x35, 0x31, 
	0x0d, 0x09, 0x05, 0x01, 0x1d, 0x19, 0x15, 0x11, 
	0x6d, 0x69, 0x65, 0x61, 0x7d, 0x79, 0x75, 0x71, 
	0x4d, 0x49, 0x45, 0x41, 0x5d, 0x59, 0x55, 0x51, 
	0xad, 0xa9, 0xa5, 0xa1, 0xbd, 0xb9, 0xb5, 0xb1, 
	0x8d, 0x89, 0x85, 0x81, 0x9d, 0x99, 0x95, 0x91, 
	0xed, 0xe9, 0xe5, 0xe1, 0xfd, 0xf9, 0xf5, 0xf1, 
	0xcd, 0xc9, 0xc5, 0xc1, 0xdd, 0xd9, 0xd5, 0xd1
};

unsigned char GFMul8[] = {
	0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 
	0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 
	0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8, 
	0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0, 0xf8, 
	0x1b, 0x13, 0x0b, 0x03, 0x3b, 0x33, 0x2b, 0x23, 
	0x5b, 0x53, 0x4b, 0x43, 0x7b, 0x73, 0x6b, 0x63, 
	0x9b, 0x93, 0x8b, 0x83, 0xbb, 0xb3, 0xab, 0xa3, 
	0xdb, 0xd3, 0xcb, 0xc3, 0xfb, 0xf3, 0xeb, 0xe3, 
	0x36, 0x3e, 0x26, 0x2e, 0x16, 0x1e, 0x06, 0x0e, 
	0x76, 0x7e, 0x66, 0x6e, 0x56, 0x5e, 0x46, 0x4e, 
	0xb6, 0xbe, 0xa6, 0xae, 0x96, 0x9e, 0x86, 0x8e, 
	0xf6, 0xfe, 0xe6, 0xee, 0xd6, 0xde, 0xc6, 0xce, 
	0x2d, 0x25, 0x3d, 0x35, 0x0d, 0x05, 0x1d, 0x15, 
	0x6d, 0x65, 0x7d, 0x75, 0x4d, 0x45, 0x5d, 0x55, 
	0xad, 0xa5, 0xbd, 0xb5, 0x8d, 0x85, 0x9d, 0x95, 
	0xed, 0xe5, 0xfd, 0xf5, 0xcd, 0xc5, 0xdd, 0xd5, 
	0x6c, 0x64, 0x7c, 0x74, 0x4c, 0x44, 0x5c, 0x54, 
	0x2c, 0x24, 0x3c, 0x34, 0x0c, 0x04, 0x1c, 0x14, 
	0xec, 0xe4, 0xfc, 0xf4, 0xcc, 0xc4, 0xdc, 0xd4, 
	0xac, 0xa4, 0xbc, 0xb4, 0x8c, 0x84, 0x9c, 0x94, 
	0x77, 0x7f, 0x67, 0x6f, 0x57, 0x5f, 0x47, 0x4f, 
	0x37, 0x3f, 0x27, 0x2f, 0x17, 0x1f, 0x07, 0x0f, 
	0xf7, 0xff, 0xe7, 0xef, 0xd7, 0xdf, 0xc7, 0xcf, 
	0xb7, 0xbf, 0xa7, 0xaf, 0x97, 0x9f, 0x87, 0x8f, 
	0x5a, 0x52, 0x4a, 0x42, 0x7a, 0x72, 0x6a, 0x62, 
	0x1a, 0x12, 0x0a, 0x02, 0x3a, 0x32, 0x2a, 0x22, 
	0xda, 0xd2, 0xca, 0xc2, 0xfa, 0xf2, 0xea, 0xe2, 
	0x9a, 0x92, 0x8a, 0x82, 0xba, 0xb2, 0xaa, 0xa2, 
	0x41, 0x49, 0x51, 0x59, 0x61, 0x69, 0x71, 0x79, 
	0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31, 0x39, 
	0xc1, 0xc9, 0xd1, 0xd9, 0xe1, 0xe9, 0xf1, 0xf9, 
	0x81, 0x89, 0x91, 0x99, 0xa1, 0xa9, 0xb1, 0xb9
};
	
static inline unsigned char *SubWord(unsigned char *w)
{
	w[0] = Sbox[w[0]];
	w[1] = Sbox[w[1]];
	w[2] = Sbox[w[2]];
	w[3] = Sbox[w[3]];

	return w;
}
	
static inline unsigned char *RotWord(unsigned char *w)
{
	unsigned char c;
	c = w[0];
	
	w[0] = w[1];
	w[1] = w[2];
	w[2] = w[3];
	w[3] = c;

	return w;
}

static unsigned char *KeyExpansion(unsigned char *key, unsigned char *w, int klen)
{
	unsigned char temp[4];
	int i, j, i4, j4, r;

	r = 4 * (klen + 7);

	for (i = 0, j = 0; i < klen; i++, j += 4) {
		memcpy(&w[i * 4], &key[j], 4);
	}

	while (i < r) {
		memcpy(&temp, &w[(i - 1) * 4], 4);

		if (i % klen == 0) {
			SubWord(RotWord(temp));
			temp[0] ^= Rcon[i/klen];
		}
		else if (klen > 6 && i % klen == 4) {
			SubWord(temp);
		}
		j = i - klen;
		i4 = i * 4;
		j4 = j * 4;
		w[i4    ] = w[j4    ] ^ temp[0];
		w[i4 + 1] = w[j4 + 1] ^ temp[1];
		w[i4 + 2] = w[j4 + 2] ^ temp[2];
		w[i4 + 3] = w[j4 + 3] ^ temp[3];

		i++;
	}
	return w;
}

static void AddRoundKey(state_t *state, unsigned char *key, int round)
{
	int i, r = round * 16, n = 0;

	for (i = 0; i < 4; i++) {
		int j;
		for (j = 0; j < 4; j++) {
			(*state)[i][j] ^= key[r + n++];
		}
	}
}

static inline void SubShiftRows(state_t *state)
{
	unsigned char c, c1;

	(*state)[0][0] = Sbox[(*state)[0][0]];
	(*state)[1][0] = Sbox[(*state)[1][0]];
	(*state)[2][0] = Sbox[(*state)[2][0]];
	(*state)[3][0] = Sbox[(*state)[3][0]];
	
	c = Sbox[(*state)[0][1]];
	(*state)[0][1] = Sbox[(*state)[1][1]];
	(*state)[1][1] = Sbox[(*state)[2][1]];
	(*state)[2][1] = Sbox[(*state)[3][1]];
	(*state)[3][1] = c;

	c = Sbox[(*state)[0][2]];
	c1 = Sbox[(*state)[1][2]];
	(*state)[0][2] = Sbox[(*state)[2][2]];
	(*state)[1][2] = Sbox[(*state)[3][2]];
	(*state)[2][2] = c;
	(*state)[3][2] = c1;

	c = Sbox[(*state)[3][3]];
	(*state)[3][3] = Sbox[(*state)[2][3]];
	(*state)[2][3] = Sbox[(*state)[1][3]];
	(*state)[1][3] = Sbox[(*state)[0][3]];
	(*state)[0][3] = c;
}  

static inline void SubInvShiftRows(state_t *state)
{
	unsigned char c, c1;

	(*state)[0][0] = InvSbox[(*state)[0][0]];
	(*state)[1][0] = InvSbox[(*state)[1][0]];
	(*state)[2][0] = InvSbox[(*state)[2][0]];
	(*state)[3][0] = InvSbox[(*state)[3][0]];

	c = InvSbox[(*state)[0][1]];
	(*state)[0][1] = InvSbox[(*state)[3][1]];
	(*state)[3][1] = InvSbox[(*state)[2][1]];
	(*state)[2][1] = InvSbox[(*state)[1][1]];
	(*state)[1][1] = c;

	c = InvSbox[(*state)[1][2]];
	c1 = InvSbox[(*state)[0][2]];
	(*state)[0][2] = InvSbox[(*state)[2][2]];
	(*state)[1][2] = InvSbox[(*state)[3][2]];
	(*state)[2][2] = c1;
	(*state)[3][2] = c;

	c = InvSbox[(*state)[1][3]];
	(*state)[1][3] = InvSbox[(*state)[2][3]];
	(*state)[2][3] = InvSbox[(*state)[3][3]];
	(*state)[3][3] = InvSbox[(*state)[0][3]];
	(*state)[0][3] = c;
}  

static void MixColumns(state_t *state)
{
	int i;  
    unsigned char ad, bc, abcd;  
	row_t *rs;

	for (i = 0; i < 4; i++) {
		rs = &(*state)[i];
		ad = (*rs)[0] ^ (*rs)[3];
		bc = (*rs)[1] ^ (*rs)[2];
		abcd = ad ^ bc;

		(*rs)[0] ^= abcd ^ GFMul2[(*rs)[0] ^ (*rs)[1]]; 
		(*rs)[1] ^= abcd ^ GFMul2[bc]; 
		(*rs)[2] ^= abcd ^ GFMul2[(*rs)[2] ^ (*rs)[3]]; 
		(*rs)[3] ^= abcd ^ GFMul2[ad];
    }  
}

static void InvMixColumns(state_t *state)
{
	int i;
    unsigned char ad, bc, p, q;  
	row_t *rs;

	for (i = 0; i < 4; i++) {      
		rs = &(*state)[i];
		ad = (*rs)[0] ^ (*rs)[3];
		bc = (*rs)[1] ^ (*rs)[2];
		q = ad ^ bc;
		q ^= GFMul8[q];
		p = q ^GFMul4[(*rs)[0] ^ (*rs)[2]];
		q = q ^GFMul4[(*rs)[1] ^ (*rs)[3]];

		(*rs)[0] ^= p ^ GFMul2[(*rs)[0] ^ (*rs)[1]]; 
		(*rs)[1] ^= q ^ GFMul2[bc]; 
		(*rs)[2] ^= p ^ GFMul2[(*rs)[2] ^ (*rs)[3]]; 
		(*rs)[3] ^= q ^ GFMul2[ad];
    }  
}

static void encryptBlock(unsigned char *in, unsigned char *out, 
						 unsigned char *w, int Nr)
{
	int round, i, j, n = 0;
	state_t state;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			state[i][j] = in[n++];
		}
	}

	AddRoundKey(&state, w, 0);

	for (round = 1; round < Nr; round++) {
		SubShiftRows(&state);
		MixColumns(&state);
		AddRoundKey(&state, w, round);
	}

	SubShiftRows(&state);
	AddRoundKey(&state, w, Nr);

	for (i = 0, n = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			out[n++] = state[i][j];
		}
	}
	
}

static void decryptBlock(unsigned char *in, unsigned char *out, 
						 unsigned char *w, int Nr)
{
	int round, i, j, n = 0;
	state_t state;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			state[i][j] = in[n++];
		}
	}

	AddRoundKey(&state, w, Nr);

	for (round = Nr-1; round > 0; round--) {
		SubInvShiftRows(&state);
		AddRoundKey(&state, w, round);
		InvMixColumns(&state);
	}

	SubInvShiftRows(&state);
	AddRoundKey(&state, w, 0);

	for (i = 0, n = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			out[n++] = state[i][j];
		}
	}
}

/*
 * ECB encryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains ciphertext on exit
 */  
int encrypt(unsigned char *input, int len, unsigned char *key, int klen)
{
	int i;
	unsigned char w[32 * 15];
	unsigned char k[32] = {0};

	if (input == 0 || key == 0) {
		return 0;
	}

	memcpy(k, key, min(klen, 32));
	KeyExpansion(k, w, 8);

	for (i = 0; i < len; i += 16) {
		encryptBlock(&input[i], &input[i], w, 14);
	}

	return 1;
}
 
/*
 * ECB decryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains cleartext on exit
 */  
int decrypt(unsigned char *input, int len, unsigned char *key, int klen)
{
	int i;
	unsigned char w[32 * 15] = {0};
	unsigned char k[32] = {0};

	if (input == 0 || key == 0) {
		return 0;
	}

	memcpy(k, key, min(klen, 32));
	KeyExpansion(k, w, 8);

	for (i = 0; i < len; i += 16) {
		decryptBlock(&input[i], &input[i], w, 14);
	}

	return 1;
}

/*
 * CBC encryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains ciphertext on exit
 * 'iv' must hold a 16 byte initialization vector
 */  
int encryptCBC(unsigned char *input, int len, unsigned char *key, int klen,
               unsigned char *iv)
{
	int i;
	unsigned char w[32 * 15];
	unsigned char k[32] = {0};
    unsigned char piv[16];

	if (input == 0 || key == 0 || iv == 0) {
		return 0;
	}

    memcpy(piv, iv, 16);

	memcpy(k, key, min(klen, 32));
	KeyExpansion(k, w, 8);

	for (i = 0; i < len; i += 16) {
        int n;
        for (n = 0; n < 16; n++) {
            input[i+n] ^= piv[n];
        }
		encryptBlock(&input[i], &input[i], w, 14);
        memcpy(piv, &input[i], 16);
	}

	return 1;
}
 
/*
 * CBC decryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains cleartext on exit
 * 'iv' must hold the same 16 byte initialization vector
 * that has been used to encrypt the cleartext
 */  
int decryptCBC(unsigned char *input, int len, unsigned char *key, int klen,
               unsigned char *iv)
{
	int i;
	unsigned char w[32 * 15] = {0};
	unsigned char k[32] = {0};
    unsigned char piv[16];
    unsigned char tpiv[16];

	if (input == 0 || key == 0 || iv == 0) {
		return 0;
	}

    memcpy(piv, iv, 16);

	memcpy(k, key, min(klen, 32));
	KeyExpansion(k, w, 8);

	for (i = 0; i < len; i += 16) {
        int n;
        memcpy(tpiv, &input[i], 16);
		decryptBlock(&input[i], &input[i], w, 14);
        for (n = 0; n < 16; n++) {
            input[i+n] ^= piv[n];
        }
        memcpy(piv, tpiv, 16);
	}

	return 1;
}

/*
 * key should not have and \r or \n 
 * character at the end to ensure compatibility
 */
void trimKey(char *key)
{
    char *cp = key;
    char *ep = &key[strlen(key)];

    while(ep > cp) {
        ep--;
        if (*ep == 0x0d || *ep == 0x0a) {
            *ep = 0x00;
        }
        else {
            break;
        }
    }
}

int aesenc(FILE *infp, SSL *ssl, char *key)
{
    long len;
    char buffer[512];
	/*
	 * ensure you use the same initialization vector
	 * for encryption and decrpytion
	 */
    unsigned char iv[] = {
        0x22, 0x10, 0x19, 0x64,
        0x10, 0x19, 0x64, 0x22,
        0x19, 0x64, 0x22, 0x10,
        0x64, 0x22, 0x10, 0x19
    };

    trimKey(key);

	/*
	 * output file starts with a 512-byte header
	 * containing magic number "ACBC"
	 * followed by a blank and the original length of the inut file
	 * the rest of the file contains a number of 512 byte blocks
	 * of ciphertext, last block is padded with 0x00
	 */
	memset(buffer, 0, sizeof(buffer));

	/*
	 * determine length of input file by setting fp to eof
	 * and reading the file position
	 */
	fseek(infp, 0, SEEK_END);
	len = ftell(infp);
	/*
	 * set fp back to bof
	 */
	fseek(infp, 0, SEEK_SET);

	/*
	 * set magic number and length and write header to output file
	 */
	sprintf(buffer, "ACBC %ld", len);
	SSL_write(ssl, buffer, sizeof(buffer));

	while (fread(buffer, sizeof(buffer), 1, infp) > 0) {
		/*
		 * encrypt 512 byte block
		 */
		encryptCBC((unsigned char*)buffer, sizeof(buffer), 
				   (unsigned char*)key, strlen(key), iv);
		/*
		 * write block to output file
		 */
		SSL_write(ssl, buffer, sizeof(buffer));
		memset(buffer, 0, sizeof(buffer));

		/*
		 * check for I/O errors
		 */
	}	
	return 0;
}

int aesdec(SSH *ssh, FILE *outfile, char *key)
{
	infp
    int n;
	long len;
    char key[512] = {0};
    char buffer[512];
//    FILE *infp, *outfp;
	/*
	 * ensure you use the same initialization vector
	 * for encryption and decrpytion
	 */
    unsigned char iv[] = {
        0x22, 0x10, 0x19, 0x64,
        0x10, 0x19, 0x64, 0x22,
        0x19, 0x64, 0x22, 0x10,
        0x64, 0x22, 0x10, 0x19
    };
 
	
    trimKey(key);

	/*
	 * read file header, check magic number
	 * and get length of original input file
	 */
	SSL_read(ssl, buffer, sizeof(buffer));
	if (memcmp(buffer, "ACBC ", 5) != 0) {
		printf("error: wrong input file format\n");
		exit(1);
	}
	sscanf(buffer, "ACBC %ld", &len);

    while ((n = SSL_read(ssl, buffer, sizeof(buffer)))>0) {
		/*
		 * read 512 byte block
		 */
        n = SSL_read(ssl, buffer, sizeof(buffer));
		if (len < 0) {
			/*
			 * we're done already so we just read until EOF
			 */
			continue;
		}
		/*
		 * decrypt block
		 */
		decryptCBC((unsigned char *)buffer, sizeof(buffer), 
				   (unsigned char *)key, strlen(key), iv);
		/*
		 * the last block may be padded with 0x00s so we have to
		 * determine how many bytes we have to take from it
		 */
		fwrite(buffer, (n > len) ? len : n, 1, outfp);
		/*
		 * calculate how many bytes still are required
		 */
		len -= n;
		memset(buffer, 0, sizeof(buffer));

		/*
		 * check for I/O errors
		 */
		
    }

	return 0;
}