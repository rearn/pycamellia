'''
pycamellia.py v 0.0

http://omake.accense.com/wiki/PythonCamellia

Portions Copyright (c) 2006 by Accense Technology, Inc.
on the work to port for Python derived from the Camellia source code
distributed as 'camellia-BSD-1.0.tar.gz'.

https://info.isl.ntt.co.jp/crypt/eng/camellia/index_s.html

Copyright (c) 2006
 NTT (Nippon Telegraph and Telephone Corporation) . All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer as
   the first lines of this file unmodified.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY NTT ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL NTT BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

__all__ = ['Ekeygen', 'EncryptBlock', 'DecryptBlock']

#
# S-box data
#
SBOX1_1110 = (
    0x70707000L, 0x82828200L, 0x2c2c2c00L, 0xececec00L, 0xb3b3b300L, 0x27272700L,
    0xc0c0c000L, 0xe5e5e500L, 0xe4e4e400L, 0x85858500L, 0x57575700L, 0x35353500L,
    0xeaeaea00L, 0x0c0c0c00L, 0xaeaeae00L, 0x41414100L, 0x23232300L, 0xefefef00L,
    0x6b6b6b00L, 0x93939300L, 0x45454500L, 0x19191900L, 0xa5a5a500L, 0x21212100L,
    0xededed00L, 0x0e0e0e00L, 0x4f4f4f00L, 0x4e4e4e00L, 0x1d1d1d00L, 0x65656500L,
    0x92929200L, 0xbdbdbd00L, 0x86868600L, 0xb8b8b800L, 0xafafaf00L, 0x8f8f8f00L,
    0x7c7c7c00L, 0xebebeb00L, 0x1f1f1f00L, 0xcecece00L, 0x3e3e3e00L, 0x30303000L,
    0xdcdcdc00L, 0x5f5f5f00L, 0x5e5e5e00L, 0xc5c5c500L, 0x0b0b0b00L, 0x1a1a1a00L,
    0xa6a6a600L, 0xe1e1e100L, 0x39393900L, 0xcacaca00L, 0xd5d5d500L, 0x47474700L,
    0x5d5d5d00L, 0x3d3d3d00L, 0xd9d9d900L, 0x01010100L, 0x5a5a5a00L, 0xd6d6d600L,
    0x51515100L, 0x56565600L, 0x6c6c6c00L, 0x4d4d4d00L, 0x8b8b8b00L, 0x0d0d0d00L,
    0x9a9a9a00L, 0x66666600L, 0xfbfbfb00L, 0xcccccc00L, 0xb0b0b000L, 0x2d2d2d00L,
    0x74747400L, 0x12121200L, 0x2b2b2b00L, 0x20202000L, 0xf0f0f000L, 0xb1b1b100L,
    0x84848400L, 0x99999900L, 0xdfdfdf00L, 0x4c4c4c00L, 0xcbcbcb00L, 0xc2c2c200L,
    0x34343400L, 0x7e7e7e00L, 0x76767600L, 0x05050500L, 0x6d6d6d00L, 0xb7b7b700L,
    0xa9a9a900L, 0x31313100L, 0xd1d1d100L, 0x17171700L, 0x04040400L, 0xd7d7d700L,
    0x14141400L, 0x58585800L, 0x3a3a3a00L, 0x61616100L, 0xdedede00L, 0x1b1b1b00L,
    0x11111100L, 0x1c1c1c00L, 0x32323200L, 0x0f0f0f00L, 0x9c9c9c00L, 0x16161600L,
    0x53535300L, 0x18181800L, 0xf2f2f200L, 0x22222200L, 0xfefefe00L, 0x44444400L,
    0xcfcfcf00L, 0xb2b2b200L, 0xc3c3c300L, 0xb5b5b500L, 0x7a7a7a00L, 0x91919100L,
    0x24242400L, 0x08080800L, 0xe8e8e800L, 0xa8a8a800L, 0x60606000L, 0xfcfcfc00L,
    0x69696900L, 0x50505000L, 0xaaaaaa00L, 0xd0d0d000L, 0xa0a0a000L, 0x7d7d7d00L,
    0xa1a1a100L, 0x89898900L, 0x62626200L, 0x97979700L, 0x54545400L, 0x5b5b5b00L,
    0x1e1e1e00L, 0x95959500L, 0xe0e0e000L, 0xffffff00L, 0x64646400L, 0xd2d2d200L,
    0x10101000L, 0xc4c4c400L, 0x00000000L, 0x48484800L, 0xa3a3a300L, 0xf7f7f700L,
    0x75757500L, 0xdbdbdb00L, 0x8a8a8a00L, 0x03030300L, 0xe6e6e600L, 0xdadada00L,
    0x09090900L, 0x3f3f3f00L, 0xdddddd00L, 0x94949400L, 0x87878700L, 0x5c5c5c00L,
    0x83838300L, 0x02020200L, 0xcdcdcd00L, 0x4a4a4a00L, 0x90909000L, 0x33333300L,
    0x73737300L, 0x67676700L, 0xf6f6f600L, 0xf3f3f300L, 0x9d9d9d00L, 0x7f7f7f00L,
    0xbfbfbf00L, 0xe2e2e200L, 0x52525200L, 0x9b9b9b00L, 0xd8d8d800L, 0x26262600L,
    0xc8c8c800L, 0x37373700L, 0xc6c6c600L, 0x3b3b3b00L, 0x81818100L, 0x96969600L,
    0x6f6f6f00L, 0x4b4b4b00L, 0x13131300L, 0xbebebe00L, 0x63636300L, 0x2e2e2e00L,
    0xe9e9e900L, 0x79797900L, 0xa7a7a700L, 0x8c8c8c00L, 0x9f9f9f00L, 0x6e6e6e00L,
    0xbcbcbc00L, 0x8e8e8e00L, 0x29292900L, 0xf5f5f500L, 0xf9f9f900L, 0xb6b6b600L,
    0x2f2f2f00L, 0xfdfdfd00L, 0xb4b4b400L, 0x59595900L, 0x78787800L, 0x98989800L,
    0x06060600L, 0x6a6a6a00L, 0xe7e7e700L, 0x46464600L, 0x71717100L, 0xbababa00L,
    0xd4d4d400L, 0x25252500L, 0xababab00L, 0x42424200L, 0x88888800L, 0xa2a2a200L,
    0x8d8d8d00L, 0xfafafa00L, 0x72727200L, 0x07070700L, 0xb9b9b900L, 0x55555500L,
    0xf8f8f800L, 0xeeeeee00L, 0xacacac00L, 0x0a0a0a00L, 0x36363600L, 0x49494900L,
    0x2a2a2a00L, 0x68686800L, 0x3c3c3c00L, 0x38383800L, 0xf1f1f100L, 0xa4a4a400L,
    0x40404000L, 0x28282800L, 0xd3d3d300L, 0x7b7b7b00L, 0xbbbbbb00L, 0xc9c9c900L,
    0x43434300L, 0xc1c1c100L, 0x15151500L, 0xe3e3e300L, 0xadadad00L, 0xf4f4f400L,
    0x77777700L, 0xc7c7c700L, 0x80808000L, 0x9e9e9e00L
)

SBOX4_4404 = (
    0x70700070L, 0x2c2c002cL, 0xb3b300b3L, 0xc0c000c0L, 0xe4e400e4L, 0x57570057L,
    0xeaea00eaL, 0xaeae00aeL, 0x23230023L, 0x6b6b006bL, 0x45450045L, 0xa5a500a5L,
    0xeded00edL, 0x4f4f004fL, 0x1d1d001dL, 0x92920092L, 0x86860086L, 0xafaf00afL,
    0x7c7c007cL, 0x1f1f001fL, 0x3e3e003eL, 0xdcdc00dcL, 0x5e5e005eL, 0x0b0b000bL,
    0xa6a600a6L, 0x39390039L, 0xd5d500d5L, 0x5d5d005dL, 0xd9d900d9L, 0x5a5a005aL,
    0x51510051L, 0x6c6c006cL, 0x8b8b008bL, 0x9a9a009aL, 0xfbfb00fbL, 0xb0b000b0L,
    0x74740074L, 0x2b2b002bL, 0xf0f000f0L, 0x84840084L, 0xdfdf00dfL, 0xcbcb00cbL,
    0x34340034L, 0x76760076L, 0x6d6d006dL, 0xa9a900a9L, 0xd1d100d1L, 0x04040004L,
    0x14140014L, 0x3a3a003aL, 0xdede00deL, 0x11110011L, 0x32320032L, 0x9c9c009cL,
    0x53530053L, 0xf2f200f2L, 0xfefe00feL, 0xcfcf00cfL, 0xc3c300c3L, 0x7a7a007aL,
    0x24240024L, 0xe8e800e8L, 0x60600060L, 0x69690069L, 0xaaaa00aaL, 0xa0a000a0L,
    0xa1a100a1L, 0x62620062L, 0x54540054L, 0x1e1e001eL, 0xe0e000e0L, 0x64640064L,
    0x10100010L, 0x00000000L, 0xa3a300a3L, 0x75750075L, 0x8a8a008aL, 0xe6e600e6L,
    0x09090009L, 0xdddd00ddL, 0x87870087L, 0x83830083L, 0xcdcd00cdL, 0x90900090L,
    0x73730073L, 0xf6f600f6L, 0x9d9d009dL, 0xbfbf00bfL, 0x52520052L, 0xd8d800d8L,
    0xc8c800c8L, 0xc6c600c6L, 0x81810081L, 0x6f6f006fL, 0x13130013L, 0x63630063L,
    0xe9e900e9L, 0xa7a700a7L, 0x9f9f009fL, 0xbcbc00bcL, 0x29290029L, 0xf9f900f9L,
    0x2f2f002fL, 0xb4b400b4L, 0x78780078L, 0x06060006L, 0xe7e700e7L, 0x71710071L,
    0xd4d400d4L, 0xabab00abL, 0x88880088L, 0x8d8d008dL, 0x72720072L, 0xb9b900b9L,
    0xf8f800f8L, 0xacac00acL, 0x36360036L, 0x2a2a002aL, 0x3c3c003cL, 0xf1f100f1L,
    0x40400040L, 0xd3d300d3L, 0xbbbb00bbL, 0x43430043L, 0x15150015L, 0xadad00adL,
    0x77770077L, 0x80800080L, 0x82820082L, 0xecec00ecL, 0x27270027L, 0xe5e500e5L,
    0x85850085L, 0x35350035L, 0x0c0c000cL, 0x41410041L, 0xefef00efL, 0x93930093L,
    0x19190019L, 0x21210021L, 0x0e0e000eL, 0x4e4e004eL, 0x65650065L, 0xbdbd00bdL,
    0xb8b800b8L, 0x8f8f008fL, 0xebeb00ebL, 0xcece00ceL, 0x30300030L, 0x5f5f005fL,
    0xc5c500c5L, 0x1a1a001aL, 0xe1e100e1L, 0xcaca00caL, 0x47470047L, 0x3d3d003dL,
    0x01010001L, 0xd6d600d6L, 0x56560056L, 0x4d4d004dL, 0x0d0d000dL, 0x66660066L,
    0xcccc00ccL, 0x2d2d002dL, 0x12120012L, 0x20200020L, 0xb1b100b1L, 0x99990099L,
    0x4c4c004cL, 0xc2c200c2L, 0x7e7e007eL, 0x05050005L, 0xb7b700b7L, 0x31310031L,
    0x17170017L, 0xd7d700d7L, 0x58580058L, 0x61610061L, 0x1b1b001bL, 0x1c1c001cL,
    0x0f0f000fL, 0x16160016L, 0x18180018L, 0x22220022L, 0x44440044L, 0xb2b200b2L,
    0xb5b500b5L, 0x91910091L, 0x08080008L, 0xa8a800a8L, 0xfcfc00fcL, 0x50500050L,
    0xd0d000d0L, 0x7d7d007dL, 0x89890089L, 0x97970097L, 0x5b5b005bL, 0x95950095L,
    0xffff00ffL, 0xd2d200d2L, 0xc4c400c4L, 0x48480048L, 0xf7f700f7L, 0xdbdb00dbL,
    0x03030003L, 0xdada00daL, 0x3f3f003fL, 0x94940094L, 0x5c5c005cL, 0x02020002L,
    0x4a4a004aL, 0x33330033L, 0x67670067L, 0xf3f300f3L, 0x7f7f007fL, 0xe2e200e2L,
    0x9b9b009bL, 0x26260026L, 0x37370037L, 0x3b3b003bL, 0x96960096L, 0x4b4b004bL,
    0xbebe00beL, 0x2e2e002eL, 0x79790079L, 0x8c8c008cL, 0x6e6e006eL, 0x8e8e008eL,
    0xf5f500f5L, 0xb6b600b6L, 0xfdfd00fdL, 0x59590059L, 0x98980098L, 0x6a6a006aL,
    0x46460046L, 0xbaba00baL, 0x25250025L, 0x42420042L, 0xa2a200a2L, 0xfafa00faL,
    0x07070007L, 0x55550055L, 0xeeee00eeL, 0x0a0a000aL, 0x49490049L, 0x68680068L,
    0x38380038L, 0xa4a400a4L, 0x28280028L, 0x7b7b007bL, 0xc9c900c9L, 0xc1c100c1L,
    0xe3e300e3L, 0xf4f400f4L, 0xc7c700c7L, 0x9e9e009eL
)

SBOX2_0222 = (
    0x00e0e0e0L, 0x00050505L, 0x00585858L, 0x00d9d9d9L, 0x00676767L, 0x004e4e4eL,
    0x00818181L, 0x00cbcbcbL, 0x00c9c9c9L, 0x000b0b0bL, 0x00aeaeaeL, 0x006a6a6aL,
    0x00d5d5d5L, 0x00181818L, 0x005d5d5dL, 0x00828282L, 0x00464646L, 0x00dfdfdfL,
    0x00d6d6d6L, 0x00272727L, 0x008a8a8aL, 0x00323232L, 0x004b4b4bL, 0x00424242L,
    0x00dbdbdbL, 0x001c1c1cL, 0x009e9e9eL, 0x009c9c9cL, 0x003a3a3aL, 0x00cacacaL,
    0x00252525L, 0x007b7b7bL, 0x000d0d0dL, 0x00717171L, 0x005f5f5fL, 0x001f1f1fL,
    0x00f8f8f8L, 0x00d7d7d7L, 0x003e3e3eL, 0x009d9d9dL, 0x007c7c7cL, 0x00606060L,
    0x00b9b9b9L, 0x00bebebeL, 0x00bcbcbcL, 0x008b8b8bL, 0x00161616L, 0x00343434L,
    0x004d4d4dL, 0x00c3c3c3L, 0x00727272L, 0x00959595L, 0x00abababL, 0x008e8e8eL,
    0x00bababaL, 0x007a7a7aL, 0x00b3b3b3L, 0x00020202L, 0x00b4b4b4L, 0x00adadadL,
    0x00a2a2a2L, 0x00acacacL, 0x00d8d8d8L, 0x009a9a9aL, 0x00171717L, 0x001a1a1aL,
    0x00353535L, 0x00ccccccL, 0x00f7f7f7L, 0x00999999L, 0x00616161L, 0x005a5a5aL,
    0x00e8e8e8L, 0x00242424L, 0x00565656L, 0x00404040L, 0x00e1e1e1L, 0x00636363L,
    0x00090909L, 0x00333333L, 0x00bfbfbfL, 0x00989898L, 0x00979797L, 0x00858585L,
    0x00686868L, 0x00fcfcfcL, 0x00ecececL, 0x000a0a0aL, 0x00dadadaL, 0x006f6f6fL,
    0x00535353L, 0x00626262L, 0x00a3a3a3L, 0x002e2e2eL, 0x00080808L, 0x00afafafL,
    0x00282828L, 0x00b0b0b0L, 0x00747474L, 0x00c2c2c2L, 0x00bdbdbdL, 0x00363636L,
    0x00222222L, 0x00383838L, 0x00646464L, 0x001e1e1eL, 0x00393939L, 0x002c2c2cL,
    0x00a6a6a6L, 0x00303030L, 0x00e5e5e5L, 0x00444444L, 0x00fdfdfdL, 0x00888888L,
    0x009f9f9fL, 0x00656565L, 0x00878787L, 0x006b6b6bL, 0x00f4f4f4L, 0x00232323L,
    0x00484848L, 0x00101010L, 0x00d1d1d1L, 0x00515151L, 0x00c0c0c0L, 0x00f9f9f9L,
    0x00d2d2d2L, 0x00a0a0a0L, 0x00555555L, 0x00a1a1a1L, 0x00414141L, 0x00fafafaL,
    0x00434343L, 0x00131313L, 0x00c4c4c4L, 0x002f2f2fL, 0x00a8a8a8L, 0x00b6b6b6L,
    0x003c3c3cL, 0x002b2b2bL, 0x00c1c1c1L, 0x00ffffffL, 0x00c8c8c8L, 0x00a5a5a5L,
    0x00202020L, 0x00898989L, 0x00000000L, 0x00909090L, 0x00474747L, 0x00efefefL,
    0x00eaeaeaL, 0x00b7b7b7L, 0x00151515L, 0x00060606L, 0x00cdcdcdL, 0x00b5b5b5L,
    0x00121212L, 0x007e7e7eL, 0x00bbbbbbL, 0x00292929L, 0x000f0f0fL, 0x00b8b8b8L,
    0x00070707L, 0x00040404L, 0x009b9b9bL, 0x00949494L, 0x00212121L, 0x00666666L,
    0x00e6e6e6L, 0x00cececeL, 0x00edededL, 0x00e7e7e7L, 0x003b3b3bL, 0x00fefefeL,
    0x007f7f7fL, 0x00c5c5c5L, 0x00a4a4a4L, 0x00373737L, 0x00b1b1b1L, 0x004c4c4cL,
    0x00919191L, 0x006e6e6eL, 0x008d8d8dL, 0x00767676L, 0x00030303L, 0x002d2d2dL,
    0x00dededeL, 0x00969696L, 0x00262626L, 0x007d7d7dL, 0x00c6c6c6L, 0x005c5c5cL,
    0x00d3d3d3L, 0x00f2f2f2L, 0x004f4f4fL, 0x00191919L, 0x003f3f3fL, 0x00dcdcdcL,
    0x00797979L, 0x001d1d1dL, 0x00525252L, 0x00ebebebL, 0x00f3f3f3L, 0x006d6d6dL,
    0x005e5e5eL, 0x00fbfbfbL, 0x00696969L, 0x00b2b2b2L, 0x00f0f0f0L, 0x00313131L,
    0x000c0c0cL, 0x00d4d4d4L, 0x00cfcfcfL, 0x008c8c8cL, 0x00e2e2e2L, 0x00757575L,
    0x00a9a9a9L, 0x004a4a4aL, 0x00575757L, 0x00848484L, 0x00111111L, 0x00454545L,
    0x001b1b1bL, 0x00f5f5f5L, 0x00e4e4e4L, 0x000e0e0eL, 0x00737373L, 0x00aaaaaaL,
    0x00f1f1f1L, 0x00ddddddL, 0x00595959L, 0x00141414L, 0x006c6c6cL, 0x00929292L,
    0x00545454L, 0x00d0d0d0L, 0x00787878L, 0x00707070L, 0x00e3e3e3L, 0x00494949L,
    0x00808080L, 0x00505050L, 0x00a7a7a7L, 0x00f6f6f6L, 0x00777777L, 0x00939393L,
    0x00868686L, 0x00838383L, 0x002a2a2aL, 0x00c7c7c7L, 0x005b5b5bL, 0x00e9e9e9L,
    0x00eeeeeeL, 0x008f8f8fL, 0x00010101L, 0x003d3d3dL
)

SBOX3_3033 = (
    0x38003838L, 0x41004141L, 0x16001616L, 0x76007676L, 0xd900d9d9L, 0x93009393L,
    0x60006060L, 0xf200f2f2L, 0x72007272L, 0xc200c2c2L, 0xab00ababL, 0x9a009a9aL,
    0x75007575L, 0x06000606L, 0x57005757L, 0xa000a0a0L, 0x91009191L, 0xf700f7f7L,
    0xb500b5b5L, 0xc900c9c9L, 0xa200a2a2L, 0x8c008c8cL, 0xd200d2d2L, 0x90009090L,
    0xf600f6f6L, 0x07000707L, 0xa700a7a7L, 0x27002727L, 0x8e008e8eL, 0xb200b2b2L,
    0x49004949L, 0xde00dedeL, 0x43004343L, 0x5c005c5cL, 0xd700d7d7L, 0xc700c7c7L,
    0x3e003e3eL, 0xf500f5f5L, 0x8f008f8fL, 0x67006767L, 0x1f001f1fL, 0x18001818L,
    0x6e006e6eL, 0xaf00afafL, 0x2f002f2fL, 0xe200e2e2L, 0x85008585L, 0x0d000d0dL,
    0x53005353L, 0xf000f0f0L, 0x9c009c9cL, 0x65006565L, 0xea00eaeaL, 0xa300a3a3L,
    0xae00aeaeL, 0x9e009e9eL, 0xec00ececL, 0x80008080L, 0x2d002d2dL, 0x6b006b6bL,
    0xa800a8a8L, 0x2b002b2bL, 0x36003636L, 0xa600a6a6L, 0xc500c5c5L, 0x86008686L,
    0x4d004d4dL, 0x33003333L, 0xfd00fdfdL, 0x66006666L, 0x58005858L, 0x96009696L,
    0x3a003a3aL, 0x09000909L, 0x95009595L, 0x10001010L, 0x78007878L, 0xd800d8d8L,
    0x42004242L, 0xcc00ccccL, 0xef00efefL, 0x26002626L, 0xe500e5e5L, 0x61006161L,
    0x1a001a1aL, 0x3f003f3fL, 0x3b003b3bL, 0x82008282L, 0xb600b6b6L, 0xdb00dbdbL,
    0xd400d4d4L, 0x98009898L, 0xe800e8e8L, 0x8b008b8bL, 0x02000202L, 0xeb00ebebL,
    0x0a000a0aL, 0x2c002c2cL, 0x1d001d1dL, 0xb000b0b0L, 0x6f006f6fL, 0x8d008d8dL,
    0x88008888L, 0x0e000e0eL, 0x19001919L, 0x87008787L, 0x4e004e4eL, 0x0b000b0bL,
    0xa900a9a9L, 0x0c000c0cL, 0x79007979L, 0x11001111L, 0x7f007f7fL, 0x22002222L,
    0xe700e7e7L, 0x59005959L, 0xe100e1e1L, 0xda00dadaL, 0x3d003d3dL, 0xc800c8c8L,
    0x12001212L, 0x04000404L, 0x74007474L, 0x54005454L, 0x30003030L, 0x7e007e7eL,
    0xb400b4b4L, 0x28002828L, 0x55005555L, 0x68006868L, 0x50005050L, 0xbe00bebeL,
    0xd000d0d0L, 0xc400c4c4L, 0x31003131L, 0xcb00cbcbL, 0x2a002a2aL, 0xad00adadL,
    0x0f000f0fL, 0xca00cacaL, 0x70007070L, 0xff00ffffL, 0x32003232L, 0x69006969L,
    0x08000808L, 0x62006262L, 0x00000000L, 0x24002424L, 0xd100d1d1L, 0xfb00fbfbL,
    0xba00babaL, 0xed00ededL, 0x45004545L, 0x81008181L, 0x73007373L, 0x6d006d6dL,
    0x84008484L, 0x9f009f9fL, 0xee00eeeeL, 0x4a004a4aL, 0xc300c3c3L, 0x2e002e2eL,
    0xc100c1c1L, 0x01000101L, 0xe600e6e6L, 0x25002525L, 0x48004848L, 0x99009999L,
    0xb900b9b9L, 0xb300b3b3L, 0x7b007b7bL, 0xf900f9f9L, 0xce00ceceL, 0xbf00bfbfL,
    0xdf00dfdfL, 0x71007171L, 0x29002929L, 0xcd00cdcdL, 0x6c006c6cL, 0x13001313L,
    0x64006464L, 0x9b009b9bL, 0x63006363L, 0x9d009d9dL, 0xc000c0c0L, 0x4b004b4bL,
    0xb700b7b7L, 0xa500a5a5L, 0x89008989L, 0x5f005f5fL, 0xb100b1b1L, 0x17001717L,
    0xf400f4f4L, 0xbc00bcbcL, 0xd300d3d3L, 0x46004646L, 0xcf00cfcfL, 0x37003737L,
    0x5e005e5eL, 0x47004747L, 0x94009494L, 0xfa00fafaL, 0xfc00fcfcL, 0x5b005b5bL,
    0x97009797L, 0xfe00fefeL, 0x5a005a5aL, 0xac00acacL, 0x3c003c3cL, 0x4c004c4cL,
    0x03000303L, 0x35003535L, 0xf300f3f3L, 0x23002323L, 0xb800b8b8L, 0x5d005d5dL,
    0x6a006a6aL, 0x92009292L, 0xd500d5d5L, 0x21002121L, 0x44004444L, 0x51005151L,
    0xc600c6c6L, 0x7d007d7dL, 0x39003939L, 0x83008383L, 0xdc00dcdcL, 0xaa00aaaaL,
    0x7c007c7cL, 0x77007777L, 0x56005656L, 0x05000505L, 0x1b001b1bL, 0xa400a4a4L,
    0x15001515L, 0x34003434L, 0x1e001e1eL, 0x1c001c1cL, 0xf800f8f8L, 0x52005252L,
    0x20002020L, 0x14001414L, 0xe900e9e9L, 0xbd00bdbdL, 0xdd00ddddL, 0xe400e4e4L,
    0xa100a1a1L, 0xe000e0e0L, 0x8a008a8aL, 0xf100f1f1L, 0xd600d6d6L, 0x7a007a7aL,
    0xbb00bbbbL, 0xe300e3e3L, 0x40004040L, 0x4f004f4fL
)


# Key generation constants
SIGMA1 = ( 0xa09e667fL, 0x3bcc908bL, 0xb67ae858L, 0x4caa73b2L )
SIGMA2 = ( 0xc6ef372fL, 0xe94f82beL, 0x54ff53a5L, 0xf1d36f1cL )
SIGMA3 = ( 0x10e527faL, 0xde682d1dL, 0xb05688c2L, 0xb3e6c1fdL )


# rotate right 8 bits
def rightRotate8(x):
    return ((x >> 8) | (x << 24)) % 0x100000000

# rotate left 1 bit
def leftRotate1(x):
    return ((x << 1) | (x >> 31)) % 0x100000000

def feistel1(x, k):
    s = x[0] ^ k[0]
    U  = SBOX4_4404[ s        & 0x000000ff]
    U ^= SBOX3_3033[(s >>  8) & 0x000000ff]
    U ^= SBOX2_0222[(s >> 16) & 0x000000ff]
    U ^= SBOX1_1110[(s >> 24) & 0x000000ff]

    s = x[1] ^ k[1]
    D  = SBOX1_1110[ s        & 0x000000ff]
    D ^= SBOX4_4404[(s >>  8) & 0x000000ff]
    D ^= SBOX3_3033[(s >> 16) & 0x000000ff]
    D ^= SBOX2_0222[(s >> 24) & 0x000000ff]

    x[2] ^= D ^ U
    x[3] ^= D ^ U ^ rightRotate8(U)

    s = x[2] ^ k[2]
    U  = SBOX4_4404[ s        & 0x000000ff]
    U ^= SBOX3_3033[(s >>  8) & 0x000000ff]
    U ^= SBOX2_0222[(s >> 16) & 0x000000ff]
    U ^= SBOX1_1110[(s >> 24) & 0x000000ff]

    s = x[3] ^ k[3]
    D  = SBOX1_1110[ s        & 0x000000ff]
    D ^= SBOX4_4404[(s >>  8) & 0x000000ff]
    D ^= SBOX3_3033[(s >> 16) & 0x000000ff]
    D ^= SBOX2_0222[(s >> 24) & 0x000000ff]

    x[0] ^= D ^ U
    x[1] ^= D ^ U ^ rightRotate8(U)

def feistel2(x, k):
    s = x[0] ^ k[2]
    U  = SBOX4_4404[ s        & 0x000000ff]
    U ^= SBOX3_3033[(s >>  8) & 0x000000ff]
    U ^= SBOX2_0222[(s >> 16) & 0x000000ff]
    U ^= SBOX1_1110[(s >> 24) & 0x000000ff]

    s = x[1] ^ k[3]
    D  = SBOX1_1110[ s        & 0x000000ff]
    D ^= SBOX4_4404[(s >>  8) & 0x000000ff]
    D ^= SBOX3_3033[(s >> 16) & 0x000000ff]
    D ^= SBOX2_0222[(s >> 24) & 0x000000ff]

    x[2] ^= D ^ U
    x[3] ^= D ^ U ^ rightRotate8(U)

    s = x[2] ^ k[0]
    U  = SBOX4_4404[ s        & 0x000000ff]
    U ^= SBOX3_3033[(s >>  8) & 0x000000ff]
    U ^= SBOX2_0222[(s >> 16) & 0x000000ff]
    U ^= SBOX1_1110[(s >> 24) & 0x000000ff]

    s = x[3] ^ k[1]
    D  = SBOX1_1110[ s        & 0x000000ff]
    D ^= SBOX4_4404[(s >>  8) & 0x000000ff]
    D ^= SBOX3_3033[(s >> 16) & 0x000000ff]
    D ^= SBOX2_0222[(s >> 24) & 0x000000ff]

    x[0] ^= D ^ U
    x[1] ^= D ^ U ^ rightRotate8(U)


import struct

# public
def Ekeygen(rawKey):
    '''Ekeygen(rawKey)

    rawKey: string; 16 or 24 or 32 character length
    returns: keyTable'''

    def rot(x, n):
        (idx, r) = divmod(n, 0x20)          # r must not be 0
        idx1 = (idx  + 1) & 0x03
        idx2 = (idx1 + 1) & 0x03
        return [
            ((x[idx ] << r) | (x[idx1] >> (32 - r))) % 0x100000000,
            ((x[idx1] << r) | (x[idx2] >> (32 - r))) % 0x100000000]

    keyLength = len(rawKey)
    if keyLength == 16:
        t = struct.unpack('!IIII', rawKey)
        u = (0, 0, 0, 0)
    elif keyLength == 24:
        t = struct.unpack('!IIIIII', rawKey)
        (t, u) = (t[0:4], t[4:6])
        u = u + (~u[0] % 0x100000000, ~u[1] % 0x100000000)
    elif keyLength == 32:
        t = struct.unpack('!IIIIIIII', rawKey)
        (t, u) = (t[0:4], t[4:8])
    else:
        raise ValueError, 'rawKey must be 16, 24 or 32 characters length.'

    if keyLength == 16:
        v = list(t)
        feistel1(v, SIGMA1)
        v = map(lambda a,b:a^b, v, t)
        feistel1(v, SIGMA2)
        t = list(t)
        t += v
        t += rot(t,  15)
        t += rot(t,  79)
        t += rot(v,  15)
        t += rot(v,  79)
        t += rot(v,  30)
        t += rot(v,  94)
        t += rot(t,  45)
        t += rot(t, 109)
        t += rot(v,  45)
        t += rot(t, 124)
        t += rot(v,  60)
        t += rot(v, 124)
        t += rot(t,  77)
        t += rot(t,  13)
        t += rot(t,  94)
        t += rot(t,  30)
        t += rot(v,  94)
        t += rot(v,  30)
        t += rot(t, 111)
        t += rot(t,  47)
        t += rot(v, 111)
        t += rot(v,  47)
        return tuple(t)

    else:
        v = map(lambda a,b:a^b, t, u)
        feistel1(v, SIGMA1)
        v = map(lambda a,b:a^b, v, t)
        feistel1(v, SIGMA2)
        w = map(lambda a,b:a^b, u, v)
        feistel1(w, SIGMA3)
        t = list(t)
        t += w
        t += rot(u,  15)
        t += rot(u,  79)
        t += rot(v,  15)
        t += rot(v,  79)
        t += rot(u,  30)
        t += rot(u,  94)
        t += rot(w,  30)
        t += rot(w,  94)
        t += rot(t,  45)
        t += rot(t, 109)
        t += rot(v,  45)
        t += rot(v, 109)
        t += rot(t,  60)
        t += rot(t, 124)
        t += rot(u,  60)
        t += rot(u, 124)
        t += rot(w,  60)
        t += rot(w, 124)
        t += rot(t,  77)
        t += rot(t,  13)
        t += rot(v,  77)
        t += rot(v,  13)
        t += rot(u,  94)
        t += rot(u,  30)
        t += rot(v,  94)
        t += rot(v,  30)
        t += rot(t, 111)
        t += rot(t,  47)
        t += rot(w, 111)
        t += rot(w,  47)
        return tuple(t)

    return keyTable


def EncryptBlock(plainText, keyTable):
    '''EncryptBlock(plainText, keyTable)

    plainText: string; plain text 16 characters
    keyTable: key generated by Ekeygen()
    returns: string; chipher text 16 characters'''

    t = list(struct.unpack('!IIII', plainText))
    t = map(lambda a,b:a^b, t, keyTable[0:4])

    feistel1(t, keyTable[4:8])
    feistel1(t, keyTable[8:12])
    feistel1(t, keyTable[12:16])
    t[1] ^= leftRotate1(t[0] & keyTable[16])
    t[0] ^= t[1] | keyTable[17]
    t[2] ^= t[3] | keyTable[19]
    t[3] ^= leftRotate1(t[2] & keyTable[18])
    feistel1(t, keyTable[20:24])
    feistel1(t, keyTable[24:28])
    feistel1(t, keyTable[28:32])
    t[1] ^= leftRotate1(t[0] & keyTable[32])
    t[0] ^= t[1] | keyTable[33]
    t[2] ^= t[3] | keyTable[35]
    t[3] ^= leftRotate1(t[2] & keyTable[34])
    feistel1(t, keyTable[36:40])
    feistel1(t, keyTable[40:44])
    feistel1(t, keyTable[44:48])

    if len(keyTable) == 52:
        # 128 bit key
        t = map(lambda a,b:a^b, (t[2], t[3], t[0], t[1]), keyTable[48:52])
    else:
        # 192 or 256 bit key
        t[1] ^= leftRotate1(t[0] & keyTable[48])
        t[0] ^= t[1] | keyTable[49]
        t[2] ^= t[3] | keyTable[51]
        t[3] ^= leftRotate1(t[2] & keyTable[50])
        feistel1(t, keyTable[52:56])
        feistel1(t, keyTable[56:60])
        feistel1(t, keyTable[60:64])
        t = map(lambda a,b:a^b, (t[2], t[3], t[0], t[1]), keyTable[64:68])

    return struct.pack('!IIII', *t)


def DecryptBlock(cipherText, keyTable):
    '''EncryptBlock(plainText, keyTable)

    cipherText: string; cipher text 16 characters
    keyTable: key generated by Ekeygen()
    returns: string; plain text 16 characters'''

    t = list(struct.unpack('!IIII', cipherText))

    if len(keyTable) == 52:
        # 128 bit key
        t = map(lambda a,b:a^b, t, keyTable[48:52])
    else:
        # 192 or 256 bit key
        t = map(lambda a,b:a^b, t, keyTable[64:68])
        feistel2(t, keyTable[60:64])
        feistel2(t, keyTable[56:60])
        feistel2(t, keyTable[52:56])
        t[1] ^= leftRotate1(t[0] & keyTable[50])
        t[0] ^= t[1] | keyTable[51]
        t[2] ^= t[3] | keyTable[49]
        t[3] ^= leftRotate1(t[2] & keyTable[48])

    feistel2(t, keyTable[44:48])
    feistel2(t, keyTable[40:44])
    feistel2(t, keyTable[36:40])
    t[1] ^= leftRotate1(t[0] & keyTable[34])
    t[0] ^= t[1] | keyTable[35]
    t[2] ^= t[3] | keyTable[33]
    t[3] ^= leftRotate1(t[2] & keyTable[32])
    feistel2(t, keyTable[28:32])
    feistel2(t, keyTable[24:28])
    feistel2(t, keyTable[20:24])
    t[1] ^= leftRotate1(t[0] & keyTable[18])
    t[0] ^= t[1] | keyTable[19]
    t[2] ^= t[3] | keyTable[17]
    t[3] ^= leftRotate1(t[2] & keyTable[16])
    feistel2(t, keyTable[12:16])
    feistel2(t, keyTable[8:12])
    feistel2(t, keyTable[4:8])

    t = map(lambda a,b:a^b, (t[2], t[3], t[0], t[1]), keyTable[0:4])
    return struct.pack('!IIII', *t)


if __name__ == '__main__':
    key128 = Ekeygen("0123456789abcdef")
    key192 = Ekeygen("0123456789abcdef01234567")
    key256 = Ekeygen("0123456789abcdef0123456789abcdef")

    plain = "0123456789abcdef"
    enc128 = EncryptBlock(plain, key128)
    dec128 = DecryptBlock(enc128, key128)
    enc192 = EncryptBlock(plain, key192)
    dec192 = DecryptBlock(enc192, key192)
    enc256 = EncryptBlock(plain, key256)
    dec256 = DecryptBlock(enc256, key256)

    assert key128 == (
        0x30313233L, 0x34353637L, 0x38396162L, 0x63646566L,
        0xbee4aba3L, 0x77ee43c1L, 0xd3b3f232L, 0xb7a1096bL,
        0x99199a1aL, 0x9b1b9c1cL, 0xb0b131b2L, 0x32b31818L,
        0x55d1bbf7L, 0x21e0e9d9L, 0xf9195bd0L, 0x84b5df72L,
        0xddfb90f0L, 0x74ecfc8cL, 0xade8425aL, 0xefb92ae8L,
        0xa6c6e707L, 0x2c2c4c6cL, 0x8cacc606L, 0x26466686L,
        0xc8783a76L, 0x7e4656f4L, 0x63031323L, 0x33435363L,
        0x1d3b3f23L, 0x2b7a1096L, 0xbbee4abaL, 0x377ee43cL,
        0x2c2c4c6cL, 0x8cacc606L, 0x26466686L, 0xa6c6e707L,
        0x98d91959L, 0x8c0c4c8cL, 0xcd0d4d8dL, 0xce0e5858L,
        0xade8425aL, 0xefb92ae8L, 0xddfb90f0L, 0x74ecfc8cL,
        0x32b31818L, 0x99199a1aL, 0x9b1b9c1cL, 0xb0b131b2L,
        0x84b5df72L, 0x55d1bbf7L, 0x21e0e9d9L, 0xf9195bd0L )

    assert key192 == (
        0x30313233L, 0x34353637L, 0x38396162L, 0x63646566L,
        0xfd057652L, 0xc26e4ca4L, 0x0af90b80L, 0x390ad47bL,
        0x99199a1aL, 0x9b1be7e7L, 0x66e665e5L, 0x64e41818L,
        0x8822fe51L, 0x12d1bd00L, 0xa155e71eL, 0xefc78edeL,
        0xcd0d4d8dL, 0xf3f3b373L, 0x32f2b272L, 0x0c0c4c8cL,
        0xb09b9329L, 0x02be42e0L, 0x0e42b51eL, 0xff415d94L,
        0xa6c6e707L, 0x2c2c4c6cL, 0x8cacc606L, 0x26466686L,
        0x44b46f40L, 0x285579c7L, 0xbbf1e3b7L, 0xa208bf94L,
        0x73839616L, 0x26364656L, 0x63031323L, 0x33435363L,
        0x7cfcecdcL, 0xccbcac9cL, 0x83031323L, 0x33435363L,
        0x40af90b8L, 0x0390ad47L, 0xbfd05765L, 0x2c26e4caL,
        0x2c2c4c6cL, 0x8cacc606L, 0x26466686L, 0xa6c6e707L,
        0x285579c7L, 0xbbf1e3b7L, 0xa208bf94L, 0x44b46f40L,
        0x32f2b272L, 0x0c0c4c8cL, 0xcd0d4d8dL, 0xf3f3b373L,
        0xf38f77e3L, 0xc76f4411L, 0x7f288968L, 0xde8050aaL,
        0x32b31818L, 0x99199a1aL, 0x9b1b9c1cL, 0xb0b131b2L,
        0x6a3dfe82L, 0xbb296137L, 0x2652057cL, 0x85c01c85L )

    assert key256 == (
        0x30313233L, 0x34353637L, 0x38396162L, 0x63646566L,
        0xb9eec79aL, 0x34da1bd7L, 0xe220590fL, 0x57ba15c5L,
        0x99199a1aL, 0x9b1b9c1cL, 0xb0b131b2L, 0x32b31818L,
        0xa35ab48cL, 0x3dc7f437L, 0x5a6a652fL, 0x6920413aL,
        0xcd0d4d8dL, 0xce0e5858L, 0x98d91959L, 0x8c0c4c8cL,
        0x8d3686f5L, 0xf8881643L, 0xd5ee8571L, 0x6e7bb1e6L,
        0xa6c6e707L, 0x2c2c4c6cL, 0x8cacc606L, 0x26466686L,
        0x0f71fd0dL, 0xd69a994bL, 0xda48104eL, 0xa8d6ad23L,
        0x73839616L, 0x26364656L, 0x63031323L, 0x33435363L,
        0x73839616L, 0x26364656L, 0x63031323L, 0x33435363L,
        0x7e220590L, 0xf57ba15cL, 0x5b9eec79L, 0xa34da1bdL,
        0x2c2c4c6cL, 0x8cacc606L, 0x26466686L, 0xa6c6e707L,
        0xd69a994bL, 0xda48104eL, 0xa8d6ad23L, 0x0f71fd0dL,
        0x98d91959L, 0x8c0c4c8cL, 0xcd0d4d8dL, 0xce0e5858L,
        0x3297b490L, 0x209d51adL, 0x5a461ee3L, 0xfa1bad35L,
        0x32b31818L, 0x99199a1aL, 0x9b1b9c1cL, 0xb0b131b2L,
        0x0ae2dcf7L, 0x63cd1a6dL, 0x0debf110L, 0x2c87abddL )

    assert enc128 == 'jr\xa9\x8b\x8a\x1d\x96f\xe8\x05\x98ot\x04tS'
    assert enc192 == '\xbd\x91\xe2\x05\x10W\xb0\xa2EA\xefJ5\x04\x95\xed'
    assert enc256 == '\xe1\xab\x1b\xa6\xa1x:\xff\xd4\x18\xb4y\xe5\xba\x9a\xf9'

    assert dec128 == plain
    assert dec192 == plain
    assert dec256 == plain

    print 'basic test ok'
