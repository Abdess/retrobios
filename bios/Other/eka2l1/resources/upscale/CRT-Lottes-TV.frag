//
// PUBLIC DOMAIN CRT STYLED SCAN-LINE SHADER
//
//   by Timothy Lottes
//
// This is more along the style of a really good CGA arcade monitor.
// With RGB inputs instead of NTSC.
// The shadow mask example has the mask rotated 90 degrees for less chromatic aberration.
//
// Left it unoptimized to show the theory behind the algorithm.
//
// It is an example what I personally would want as a display option for pixel art games.
// Please take and use, change, or whatever.
//
// ported, tweaked, fast, TV version by guest.r

#ifdef GL_ES
precision mediump float;
precision mediump int;
#endif

uniform sampler2D sampler0;
in vec2 r_texcoord;

uniform vec2 u_texelDelta;
uniform vec2 u_pixelDelta; 

out vec4 o_color;

const vec2 OGLSize    = vec2(480.0,272.0);


// CRT-Lottes settings (editable)

#define shadowMask 1              // 1, 2, 3 or 4 (CRT style)
#define maskDark 0.6             
#define maskLight 1.4           
#define hardScan -7.0
#define hardPix -2.5
#define warpX 0.045              // x-curvature setting, 0.0 - 0.1
#define warpY 0.041              // y-curvature setting, 0.0 - 0.1
#define shape 2.0
#define brightboost 1.1
#define GAMMA  0.416             // output gamma, 0.5 is default


#define warp vec2(warpX,warpY)

vec3 TV (vec2 pos)
{	
	vec2 dx = vec2(0.002083333, 0.0);
	vec3 D = texture(sampler0, pos  -dx   ).rgb;	
	vec3 E = texture(sampler0, pos        ).rgb;
	vec3 F = texture(sampler0, pos  +dx   ).rgb;
	
	vec3 G =  F - D + E;
	
	float le = dot(E,E);
	float lg = dot(G,G);
	float cs = length(G-E);
	cs = min(0.2, 0.7*cs);
		
	if(lg < le) E*= vec3(1.0, 1.0-cs, 1.0);
	if(lg > le) E*= vec3(1.0-cs, 1.0, 1.0-cs);
	
	return E;	
}

vec3 ToLinear(vec3 c)
{
   return c*c;
}

// Linear to sRGB.
// Assuming using sRGB typed textures this should not be needed.

vec3 ToSrgb(vec3 c)
{
   return pow(c,vec3(GAMMA));
}

// Nearest emulated sample given floating point position and texel offset.
vec3 Fetch(vec2 pos,vec2 off){
  pos=(floor(pos*OGLSize.xy+off)+vec2(0.5,0.5))/OGLSize;
  return ToLinear(TV(pos.xy).xyz);
}

// Distance in emulated pixels to nearest texel.
vec2 Dist(vec2 pos){pos=pos*OGLSize.xy;return -((pos-floor(pos))-vec2(0.5));}
    
// 1D Gaussian.
float Gaus(float pos,float scale){return exp2(scale*pow(abs(pos),shape));}

// 3-tap Gaussian filter along horz line.
vec3 Horz3(vec2 pos,float off){
  vec3 b=Fetch(pos,vec2(-1.0,off));
  vec3 c=Fetch(pos,vec2( 0.0,off));
  vec3 d=Fetch(pos,vec2( 1.0,off));
  float dst=Dist(pos).x;
  // Convert distance to weight.
  float scale=hardPix;
  float wb=Gaus(dst-1.0,scale);
  float wc=Gaus(dst+0.0,scale);
  float wd=Gaus(dst+1.0,scale);
  // Return filtered sample.
  return (b*wb+c*wc+d*wd)/(wb+wc+wd);}
  
// 5-tap Gaussian filter along horz line.
vec3 Horz5(vec2 pos,float off){
  vec3 a=Fetch(pos,vec2(-2.0,off));
  vec3 b=Fetch(pos,vec2(-1.0,off));
  vec3 c=Fetch(pos,vec2( 0.0,off));
  vec3 d=Fetch(pos,vec2( 1.0,off));
  vec3 e=Fetch(pos,vec2( 2.0,off));
  float dst=Dist(pos).x;
  // Convert distance to weight.
  float scale=hardPix;
  float wa=Gaus(dst-2.0,scale);
  float wb=Gaus(dst-1.0,scale);
  float wc=Gaus(dst+0.0,scale);
  float wd=Gaus(dst+1.0,scale);
  float we=Gaus(dst+2.0,scale);
  // Return filtered sample.
  return (a*wa+b*wb+c*wc+d*wd+e*we)/(wa+wb+wc+wd+we);}


// Return scanline weight.
float Scan(vec2 pos,float off){
  float dst=Dist(pos).y;
  return Gaus(dst+off,hardScan);}
  

// Allow nearest three lines to effect pixel.
vec3 Tri(vec2 pos){
  vec3 a=Horz3(pos,-1.0);
  vec3 b=Horz5(pos, 0.0);
  vec3 c=Horz3(pos, 1.0);
  float wa=Scan(pos,-1.0);
  float wb=Scan(pos, 0.0);
  float wc=Scan(pos, 1.0);
  return a*wa+b*wb+c*wc;}
  

// Distortion of scanlines, and end of screen alpha.
vec2 Warp(vec2 pos){
  pos=pos*2.0-1.0;    
  pos*=vec2(1.0+(pos.y*pos.y)*warp.x,1.0+(pos.x*pos.x)*warp.y);
  return pos*0.5+0.5;}

// Shadow mask 
vec3 Mask(vec2 pos) {
	vec3 mask=vec3(maskDark,maskDark,maskDark);

	// Very compressed TV style shadow mask.
	if (shadowMask == 1) {
		float lineM = maskLight;
		float oddM = 0.0;

		if(fract(pos.x / 6.0) < 0.5) oddM = 1.0;
		if(fract((pos.y + oddM) / 2.0) < 0.5) lineM = maskDark;
		pos.x= fract(pos.x / 3.0);

		if(pos.x < 0.333) mask.r = maskLight;
		else if(pos.x < 0.666) mask.g = maskLight;
		else mask.b = maskLight;
		mask *= lineM;
	} else if (shadowMask == 2) {
		// Aperture-grille.
		pos.x = fract(pos.x / 3.0);

		if(pos.x < 0.333) mask.r = maskLight;
		else if(pos.x < 0.666) mask.g = maskLight;
		else mask.b=maskLight;
	} else if (shadowMask == 3) {
		// Stretched VGA style shadow mask (same as prior shaders).
		pos.x += pos.y * 3.0;
		pos.x = fract(pos.x / 6.0);

		if(pos.x < 0.333) mask.r = maskLight;
		else if(pos.x < 0.666) mask.g = maskLight;
		else mask.b = maskLight;
	} else if (shadowMask == 4) {
		// VGA style shadow mask.
		pos.xy = floor(pos.xy * vec2(1.0,0.5));
		pos.x += pos.y * 3.0;
		pos.x = fract(pos.x / 6.0);

		if(pos.x < 0.333) mask.r = maskLight;
		else if(pos.x < 0.666) mask.g = maskLight;
		else mask.b = maskLight;
	}

	return mask;
}

  
/*  CRT shader - corner function

    Copyright (C) 2010-2012 cgwg, Themaister and DOLLS

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the Free
    Software Foundation; either version 2 of the License, or (at your option)
    any later version.

    (cgwg gave their consent to have the original version of this shader
    distributed under the GPL in this message:

        http://board.byuu.org/viewtopic.php?p=26075#p26075

        "Feel free to distribute my shaders under the GPL. After all, the
        barrel distortion code was taken from the Curvature shader, which is
        under the GPL."
    )
*/
	
  float corner(vec2 coord)
  {
                coord = (coord - vec2(0.5)) * 1.0 + vec2(0.5);
                coord = min(coord, vec2(1.0)-coord) * vec2(1.0, 0.5666667);
                vec2 cdist = vec2(0.04);
                coord = (cdist - min(coord,cdist));
                float dist = sqrt(dot(coord,coord));
                return clamp((cdist.x-dist)*200.0,0.0, 1.0);
  }  

  
void main()
{
	vec2 OGL2bPos = (r_texcoord + vec2(0.000001)) * (1.0/u_pixelDelta.xy);
	vec2 pos = Warp(r_texcoord);
	vec3 color = Tri(pos)*brightboost;
	color = min(color,1.0);
	color = pow(color, vec3(1.2));	
	color*= Mask(OGL2bPos); // Tweak by SimoneT
	color = ToSrgb(color);
	float black = 1.0;
	if (pos.x < 0.0 || pos.x > 1.0 || pos.y < 0.0 || pos.y > 1.0) black = 0.0;
	o_color.rgb = color*black*corner(pos);
	o_color.a= 1.0;
}
