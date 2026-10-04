// Based on the AMD FidelityFX Super Resolution 1.0 sample.
// Copyright(c) 2021 Advanced Micro Devices, Inc.All rights reserved.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// The #version line and FSR_PASS_EASU come from the backend, because FSR_EASU_F/FSR_RCAS_F are
// preprocessor gates deciding which function bodies ffx_fsr1.h emits at all. Selecting the pass
// with a specialization constant the way cas.glsl does would leave both calls unresolved.

#define A_GPU 1
#define A_GLSL 1

// FSR needs the 2021 revision of the portability header; ffx_a.h in this directory is the 2019 one
// that ffx_cas.h and the Metal backend are patched against, and must not be used here.
#include "ffx_a_fsr1.h"

// Both passes share this block so that one pipeline layout serves both. RCAS only reads Const0 and
// Sample, but Sample sits at offset 64 regardless, so the host has to push all five vectors.
layout(push_constant) uniform const_buffer
{
    uvec4 Const0;
    uvec4 Const1;
    uvec4 Const2;
    uvec4 Const3;
    uvec4 Sample;
};

// EASU reads through textureGather, so unlike CAS this has to be a combined image sampler rather
// than a plain sampled image.
layout(set=0, binding=0) uniform sampler2D imgSrc;
layout(set=0, binding=1, rgba8) uniform writeonly image2D imgDst;

#if FSR_PASS_EASU
    #define FSR_EASU_F 1
    AF4 FsrEasuRF(AF2 p) { return textureGather(imgSrc, p, 0); }
    AF4 FsrEasuGF(AF2 p) { return textureGather(imgSrc, p, 1); }
    AF4 FsrEasuBF(AF2 p) { return textureGather(imgSrc, p, 2); }
#else
    #define FSR_RCAS_F 1
    AF4 FsrRcasLoadF(ASU2 p) { return texelFetch(imgSrc, ASU2(p), 0); }
    // Our input is already linear and between 0 and 1, so nothing to transform. See ffx_fsr1.h
    void FsrRcasInputF(inout AF1 r, inout AF1 g, inout AF1 b) {}
#endif

#include "ffx_fsr1.h"

void CurrFilter(AU2 pos)
{
    AF3 c;
#if FSR_PASS_EASU
    FsrEasuF(c, pos, Const0, Const1, Const2, Const3);
#else
    FsrRcasF(c.r, c.g, c.b, pos, Const0);
#endif

    // Sample.x selects AMD's gamma2 output path, which we never want - the host zeroes it. It is
    // read unconditionally, so a short push constant write would square the whole image.
    if (Sample.x == 1u)
        c *= c;

    imageStore(imgDst, ASU2(pos), AF4(c, 1.0));
}

layout(local_size_x=64) in;
void main()
{
    // Do remapping of local xy in workgroup for a more PS-like swizzle pattern.
    AU2 gxy = ARmp8x8(gl_LocalInvocationID.x)+AU2(gl_WorkGroupID.x<<4u,gl_WorkGroupID.y<<4u);

    CurrFilter(gxy);
    gxy.x += 8u;

    CurrFilter(gxy);
    gxy.y += 8u;

    CurrFilter(gxy);
    gxy.x -= 8u;

    CurrFilter(gxy);
}
