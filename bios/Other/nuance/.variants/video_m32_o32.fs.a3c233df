/*
Nuance pixel shader for 16/32-bit pixel modes:

This pixel shader blends together two 16/32-bit YCrCbA format textures.  The alpha
component for each pixel is expected to be a measure of transparency and not
opacity as is usually the case in OpenGL.  The first set of texture coordinates
should correspond to the main video channel and the second set of texture 
coordinates should correspond to the overlay video channel.  Invalid YCrCbA
pixels of (0.0, 0.0, 0.0, X.X) are considered to be transparent for the overlay
channel only.

The CCIR-601 definition of YCrCb is used.  This means that the valid integer range
of Y is [16,235] and the valid integer range of Cr and Cb is [16,240].

After converting the texels to RGBA, the main channel texel is blended 
with the overlay channel texel using the the overlay texel alpha value to
determine the transparency factor for the overlay color.  That is, the final
color is [mainColor * (1 - overlayColor.a)] + (overlayColor * overlayColor.a)

Note: Post-bias is not needed in this shader because the chromiance values
are being biased to [-0.5,0.5] unlike when using the imaging subset where
all intermediate values are required to stay within the range [0.0,1.0]
*/

uniform sampler2D mainChannelSampler;
uniform sampler2D overlayChannelSampler;
uniform sampler2D LUTSampler;

uniform float structOverlayChannelAlpha;
uniform float mainIs16bit;

uniform float resy;

uniform vec4 scaleInternal; // main buffer xy and overlay buffer xy

const vec3 preBiasExpansion = vec3(16.0/219.0,16.0/224.0,16.0/224.0);
const float chromianceBias = 0.5;
const vec3 expansion = vec3(255.0/219.0,255.0/224.0,255.0/224.0);

vec3 ycrcb2rgb(vec3 ycrcb)
{
  ycrcb.yz -= chromianceBias;
  return vec3(ycrcb.x+1.402*ycrcb.y, ycrcb.x-0.34413*ycrcb.z-0.714136*ycrcb.y, ycrcb.x+1.772*ycrcb.z);
}

vec3 texture2D_main(vec2 uv_org)
{
  vec2 LUT[4];
  if(mainIs16bit != 0.)
  for(int i = 0; i < 4; ++i)
  {
    vec2 uv = uv_org;
    if(i == 1 || i == 3)
      uv.x += 1.;
    if(i > 1)
      uv.y += 1.;
    uv = clamp(uv,vec2(0.,0.),vec2((720.0-1.0)*scaleInternal.x,(resy-1.)*scaleInternal.y));
    uv *= vec2(0.0013888889,1./resy); // 1./720

    LUT[i] = texture2D(mainChannelSampler, uv).yx;
  }

  vec3 bilerp[4];
  for(int i = 0; i < 4; ++i)
  {
    vec3 mainColor;
    if(mainIs16bit != 0.)
      mainColor = texture2D(LUTSampler, LUT[i]).xyz;
    else
    {
      vec2 uv = uv_org;
      if(i == 1 || i == 3)
        uv.x += 1.;
      if(i > 1)
        uv.y += 1.;
      uv = clamp(uv,vec2(0.,0.),vec2((720.0-1.0)*scaleInternal.x,(resy-1.)*scaleInternal.y));
      uv *= vec2(0.0013888889,1./resy); // 1./720

      mainColor = texture2D(mainChannelSampler, uv).bgr; //!! throws away alpha, but should not matter as this is the final displayed buffer anyway!
    }

    mainColor = clamp(mainColor*expansion-preBiasExpansion, 0.0, 1.0);
    bilerp[i] = clamp(ycrcb2rgb(mainColor), 0.0, 1.0);
  }

  vec2 bilerpw = fract(uv_org);
  // smoothstep:
  bilerpw = bilerpw*bilerpw*(3.-2.*bilerpw); //bilerpw = bilerpw*bilerpw*bilerpw*(bilerpw*(bilerpw*6.0-15.0)+10.0);
  return   bilerp[0]*(1.-bilerpw.y-(bilerpw.x-bilerpw.x*bilerpw.y))
         + bilerp[1]*(bilerpw.x-bilerpw.x*bilerpw.y)
         + bilerp[2]*(bilerpw.y-bilerpw.x*bilerpw.y)
         + bilerp[3]*(bilerpw.x*bilerpw.y);
}

vec4 texture2D_overlay(vec2 uv_org)
{
  vec2 LUT[4];
  if(structOverlayChannelAlpha >= 0.)
  for(int i = 0; i < 4; ++i)
  {
    vec2 uv = uv_org;
    if(i == 1 || i == 3)
      uv.x += 1.;
    if(i > 1)
      uv.y += 1.;
    uv = clamp(uv,vec2(0.,0.),vec2((720.0-1.0)*scaleInternal.z,(resy-1.)*scaleInternal.w));
    uv *= vec2(0.0013888889,1./resy); // 1./720

    LUT[i] = texture2D(overlayChannelSampler, uv).yx;
  }

  vec4 bilerp[4];
  for(int i = 0; i < 4; ++i)
  {
    vec4 overlayColor;
    if(structOverlayChannelAlpha >= 0.)
      overlayColor = vec4(texture2D(LUTSampler, LUT[i]).xyz,structOverlayChannelAlpha);
    else
    {
      vec2 uv = uv_org;
      if(i == 1 || i == 3)
        uv.x += 1.;
      if(i > 1)
        uv.y += 1.;
      uv = clamp(uv,vec2(0.,0.),vec2((720.0-1.0)*scaleInternal.z,(resy-1.)*scaleInternal.w));
      uv *= vec2(0.0013888889,1./resy); // 1./720

      overlayColor = texture2D(overlayChannelSampler, uv).bgra;
    }

    if(overlayColor.xyz == vec3(0.0,0.0,0.0)) // invalid overlay pixel -> fully transparent overlay pixel //!! should this also be interpolated??
      return vec4(overlayColor.xyz,1.0);

    overlayColor.xyz = clamp(overlayColor.xyz*expansion-preBiasExpansion, 0.0, 1.0);
    overlayColor.rgb = clamp(ycrcb2rgb(overlayColor.xyz), 0.0, 1.0);

    bilerp[i] = overlayColor;
  }

  vec2 bilerpw = fract(uv_org);
  // smoothstep:
  bilerpw = bilerpw*bilerpw*(3.-2.*bilerpw); //bilerpw = bilerpw*bilerpw*bilerpw*(bilerpw*(bilerpw*6.0-15.0)+10.0);
  return   bilerp[0]*(1.-bilerpw.y-(bilerpw.x-bilerpw.x*bilerpw.y))
         + bilerp[1]*(bilerpw.x-bilerpw.x*bilerpw.y)
         + bilerp[2]*(bilerpw.y-bilerpw.x*bilerpw.y)
         + bilerp[3]*(bilerpw.x*bilerpw.y);
}

vec3 texture2D_composite(vec2 mainuv, vec2 overlayuv)
{
  vec3 mainColor;
  if(mainIs16bit >= 0.) // main buffer enabled?
    mainColor = texture2D_main(mainuv);
  else
    mainColor = vec3(0.,0.,0.); //!! ?? or disable mixing with it completely then?

  if(structOverlayChannelAlpha == 1.0) // overlay buffer not enabled? or fully transparent?
    return mainColor;

  vec4 overlayColor = texture2D_overlay(overlayuv);

  //On the Nuon, alpha represents transparency with 0x00 being fully opaque.
  return mix(mainColor, overlayColor.rgb, 1.0 - overlayColor.a);
}

void main()
{
  vec2 mainuv    = gl_TexCoord[0].st*vec2(720.,resy)-0.499; //!! 0.499 because of precision problems if src width/height is rather small (Space Invaders XL)
  vec2 overlayuv = gl_TexCoord[1].st*vec2(720.,resy)-0.499; //!! dto.

  gl_FragColor = vec4(texture2D_composite(mainuv, overlayuv), 1.0);
}
