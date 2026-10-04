// Snapdragon Game Super Resolution 1.0, "mobile" variant.
//
// SPDX-FileCopyrightText: Copyright (c) 2025, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// The filter body below is Qualcomm's, unchanged in substance. What differs from their sample is
// the shape around it: theirs is a fragment shader over a fullscreen triangle, and this is a
// compute pass, because that is what GSDevice already knows how to schedule (see fsr1.glsl and
// DoFSR1Pass). So the interpolated texcoord becomes an explicit UV computed from the invocation
// id, and the fragment output becomes an imageStore.
//
// The crop handling comes from the Eden Emulator Project's port (GPL-3.0-or-later), which found
// that the source rect has to be mapped explicitly rather than assumed to be the whole texture --
// PCSX2 hands us a display rectangle inside a larger target for exactly the same reason FSR1's
// FsrEasuConOffset takes an offset. The sharpness range being 0..2 rather than 0..1 comes from
// there too; the original was too tight to be useful at the top end.
//
// Brought to ARMSX2 at the suggestion of CamilleLaVey, who authored the Eden changes this is
// based on (eden-emu/eden PR #4293).

#define EDGE_THRESHOLD (8.0 / 255.0)
#define DIRECTION_EPSILON 6.5e-05
#define DEVIATION_FLOOR 6.0e-02

layout(push_constant) uniform const_buffer
{
    // Output extent, for the bounds check. A dispatch is rounded up to whole workgroups, so the
    // last one runs partly outside the image.
    uvec2 dstSize;
    // The displayed region inside the source texture, normalised. PCSX2's merge target is bigger
    // than the picture in it; without this the filter would upscale the padding too.
    vec2 uvOffset;
    vec2 uvScale;
    // Source texture dimensions and their reciprocal. Qualcomm's "size" and "scale".
    vec2 srcSize;
    vec2 invSrcSize;
    // 0..2. 1.0 is Qualcomm's own default; above that is oversharpened and is offered because
    // the range was too tight to be useful at the top end.
    float edgeSharpness;
};

layout(set = 0, binding = 0) uniform sampler2D imgSrc;
layout(set = 0, binding = 1, rgba8) uniform writeonly image2D imgDst;

#if SGSR_EDGE_DIRECTION

// ---- Edge-direction variant -------------------------------------------------------------
// Qualcomm's higher-quality mobile shader: it estimates the direction of the edge under the
// pixel and weights a fast Lanczos-2 kernel along it, where the plain variant weights an
// isotropic one. More texture gathers and more arithmetic for a cleaner reconstruction.
//
// ViewportInfo[0].xy/.zw in Qualcomm's original are 1/size and size, which are invSrcSize and
// srcSize here — so both variants share one push-constant block and one pipeline layout.

float fastLanczos2(float x)
{
    float wA = x - 4.0f;
    float wB = x * wA - wA;
    wA *= wA;
    return wB * wA;
}

vec2 weightYEdge(float dx, float dy, float c, vec3 data)
{
    float std = data.x;
    vec2 dir = data.yz;
    float edgeDis = ((dx * dir.y) + (dy * dir.x));
    float x = (((dx * dx) + (dy * dy)) +
        ((edgeDis * edgeDis) * ((clamp(((c * c) * std), 0.0f, 1.0f) * 0.7f) + -1.0f)));
    float w = fastLanczos2(x);
    return vec2(w, w * c);
}

vec2 edgeDirection(vec4 left, vec4 right)
{
    vec2 dir;
    float RxLz = (right.x + (-left.z));
    float RwLy = (right.w + (-left.y));
    vec2 delta;
    delta.x = (RxLz + RwLy);
    delta.y = (RxLz + (-RwLy));
    float lengthInv = inversesqrt((delta.x * delta.x + 3.075740e-05f) + (delta.y * delta.y));
    dir.x = (delta.x * lengthInv);
    dir.y = (delta.y * lengthInv);
    return dir;
}

#else

// Revised upstream maths (eden-emu PR #4257, CamilleLaVey). The plain variant is no longer
// isotropic: it estimates the edge direction and weights a fast Lanczos-2 kernel along it, which
// is what the edge-direction shader was for -- but it does so from the three texture gathers it
// already had rather than the four that one takes. DEVIATION_FLOOR guards the reciprocal, which
// previously divided by a sum that can be zero on a flat block.
mediump vec4 fastLanczos2(mediump vec4 x)
{
    mediump vec4 wA = x - 4.0f;
    mediump vec4 wB = x * wA - wA;
    wA *= wA;
    return wB * wA;
}

mediump vec2 edgeDirection(mediump vec4 left, mediump vec4 right)
{
    mediump float RxLz = right.x - left.z;
    mediump float RwLy = right.w - left.y;
    mediump vec2 delta = vec2(RxLz + RwLy, RxLz - RwLy);
    mediump float length_inv =
        inversesqrt((delta.x * delta.x + DIRECTION_EPSILON) + delta.y * delta.y);
    return delta * length_inv;
}

mediump vec4 weightY(mediump vec4 dx, mediump vec4 dy, mediump vec4 c, mediump float std,
                     mediump vec2 dir)
{
    mediump vec4 edge_dis = dx * dir.y + dy * dir.x;
    mediump vec4 x = (dx * dx + dy * dy) +
                     (edge_dis * edge_dis) * (clamp((c * c) * std, 0.0f, 1.0f) * 0.7f - 1.0f);
    return fastLanczos2(x);
}

#endif

layout(local_size_x = 8, local_size_y = 8) in;
void main()
{
    const uvec2 pos = gl_GlobalInvocationID.xy;
    if (pos.x >= dstSize.x || pos.y >= dstSize.y)
        return;

    // Centre of this output pixel, mapped into the displayed region of the source.
    const vec2 texcoord = uvOffset + ((vec2(pos) + vec2(0.5f)) / vec2(dstSize)) * uvScale;

    vec4 color = textureLod(imgSrc, texcoord, 0.0f);

#if SGSR_EDGE_DIRECTION
    vec2 imgCoord = ((texcoord * srcSize) + vec2(-0.5f, 0.5f));
    vec2 imgCoordPixel = floor(imgCoord);
    vec2 coord = (imgCoordPixel * invSrcSize);
    vec2 pl = imgCoord - imgCoordPixel;
    vec4 left = textureGather(imgSrc, coord, 1);
    float edgeVote = abs(left.z - left.y) + abs(color.y - left.y) + abs(color.y - left.z);
    if (edgeVote > EDGE_THRESHOLD)
    {
        coord.x += invSrcSize.x;

        vec4 right = textureGather(imgSrc, coord + vec2(invSrcSize.x, 0.0f), 1);
        vec4 upDown;
        upDown.xy = textureGather(imgSrc, coord + vec2(0.0f, -invSrcSize.y), 1).wz;
        upDown.zw = textureGather(imgSrc, coord + vec2(0.0f, invSrcSize.y), 1).yx;

        float mean = (left.y + left.z + right.x + right.w) * 0.25f;
        left = left - vec4(mean);
        right = right - vec4(mean);
        upDown = upDown - vec4(mean);
        color.w = color.y - mean;

        float sum = (((((abs(left.x) + abs(left.y)) + abs(left.z)) + abs(left.w)) +
            (((abs(right.x) + abs(right.y)) + abs(right.z)) + abs(right.w))) +
            (((abs(upDown.x) + abs(upDown.y)) + abs(upDown.z)) + abs(upDown.w)));
        float sumMean = 1.014185e+01f / sum;
        float std = (sumMean * sumMean);

        vec3 data = vec3(std, edgeDirection(left, right));
        vec2 aWY = weightYEdge(pl.x, pl.y + 1.0f, upDown.x, data);
        aWY += weightYEdge(pl.x - 1.0f, pl.y + 1.0f, upDown.y, data);
        aWY += weightYEdge(pl.x - 1.0f, pl.y - 2.0f, upDown.z, data);
        aWY += weightYEdge(pl.x, pl.y - 2.0f, upDown.w, data);
        aWY += weightYEdge(pl.x + 1.0f, pl.y - 1.0f, left.x, data);
        aWY += weightYEdge(pl.x, pl.y - 1.0f, left.y, data);
        aWY += weightYEdge(pl.x, pl.y, left.z, data);
        aWY += weightYEdge(pl.x + 1.0f, pl.y, left.w, data);
        aWY += weightYEdge(pl.x - 1.0f, pl.y - 1.0f, right.x, data);
        aWY += weightYEdge(pl.x - 2.0f, pl.y - 1.0f, right.y, data);
        aWY += weightYEdge(pl.x - 2.0f, pl.y, right.z, data);
        aWY += weightYEdge(pl.x - 1.0f, pl.y, right.w, data);

        float finalY = aWY.y / aWY.x;
        float maxY = max(max(left.y, left.z), max(right.x, right.w));
        float minY = min(min(left.y, left.z), min(right.x, right.w));
        float deltaY = clamp(edgeSharpness * finalY, minY, maxY) - color.w;

        // smooth high contrast input
        deltaY = clamp(deltaY, -23.0f / 255.0f, 23.0f / 255.0f);

        color.x = clamp((color.x + deltaY), 0.0f, 1.0f);
        color.y = clamp((color.y + deltaY), 0.0f, 1.0f);
        color.z = clamp((color.z + deltaY), 0.0f, 1.0f);
    }
#else
    // image coord
    vec2 icoord = (texcoord * srcSize + vec2(-0.5f, 0.5f));
    vec2 icoord_pixel = floor(icoord);
    vec2 coord = icoord_pixel * invSrcSize;
    vec2 pl = icoord - icoord_pixel;
    // left: 0, right: 1, upDown: 2
    mat3x4 dg = mat3x4(
        textureGather(imgSrc, coord, 1),
        textureGather(imgSrc, coord + vec2(2.f * invSrcSize.x, 0.0f), 1),
        vec4(
            textureGather(imgSrc, coord + vec2(invSrcSize.x, -invSrcSize.y), 1).wz,
            textureGather(imgSrc, coord + vec2(invSrcSize.x, +invSrcSize.y), 1).yx
        )
    );
    float edgeVote = abs(dg[0].z - dg[0].y) + abs(color.y - dg[0].y) + abs(color.y - dg[0].z);
    if (edgeVote > EDGE_THRESHOLD)
    {
        mediump float mean = (dg[0].y + dg[0].z + dg[1].x + dg[1].w) * 0.25f;
        dg = dg - mean;
        mediump float sum = dot(abs(dg[0]) + abs(dg[1]) + abs(dg[2]), vec4(1.0f));
        // max() against the floor: a flat block sums to zero and the reciprocal blew up.
        mediump float sum_mean = 1.014185e+01f / max(sum, DEVIATION_FLOOR);
        mediump float std = sum_mean * sum_mean;
        mediump vec2 dir = edgeDirection(dg[0], dg[1]);
        mediump vec4 w0 = weightY(
            pl.xxxx + vec4(+1.0f, +0.0f, +0.0f, +1.0f),
            pl.yyyy + vec4(-1.0f, -1.0f, +0.0f, +0.0f),
            dg[0], std, dir
        );
        mediump vec4 w1 = weightY(
            pl.xxxx + vec4(-1.0f, -2.0f, -2.0f, -1.0f),
            pl.yyyy + vec4(-1.0f, -1.0f, +0.0f, +0.0f),
            dg[1], std, dir
        );
        mediump vec4 w2 = weightY(
            pl.xxxx + vec4(+0.0f, -1.0f, -1.0f, +0.0f),
            pl.yyyy + vec4(+1.0f, +1.0f, -2.0f, -2.0f),
            dg[2], std, dir
        );
        mediump float sum_w = dot(w0 + w1 + w2, vec4(1.0f));
        mediump float sum_wc = dot(w0 * dg[0] + w1 * dg[1] + w2 * dg[2], vec4(1.0f));
        mediump vec2 yb = vec2(
            min(min(dg[0].y, dg[0].z), min(dg[1].x, dg[1].w)),
            max(max(dg[0].y, dg[0].z), max(dg[1].x, dg[1].w))
        );
        mediump float fy = clamp((sum_wc / sum_w) * edgeSharpness, yb[0], yb[1]);
        mediump float dy = clamp(fy - color.y + mean, -23.0f / 255.0f, 23.0f / 255.0f);
        color = clamp(color + dy, 0.0f, 1.0f);
    }
#endif
    color.w = 1.0f; // assume alpha channel is not used
    imageStore(imgDst, ivec2(pos), color);
}
