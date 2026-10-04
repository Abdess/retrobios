/*
	dot fragment shader
	
	Original code by Themaister, released into the public domain
	
	'Ported' (i.e. copy/paste) to PPSSPP format by jdgleaver
	
	This program is free software; you can redistribute it and/or modify it
	under the terms of the GNU General Public License as published by the Free
	Software Foundation; either version 2 of the License, or (at your option)
	any later version.
*/

//=== Config
#define gamma 2.4  // "Dot Gamma" - default: 2.4,  min: 0.0, max: 5.0, step: 0.05
#define shine 0.05 // "Dot Shine" - default: 0.05, min: 0.0, max: 0.5, step: 0.01
#define blend 0.65 // "Dot Blend" - default: 0.65, min: 0.0, max: 1.0, step: 0.01

//================
#ifdef GL_ES
//precision mediump float;
//precision mediump int;
// For android, use this instead...
precision highp float;
precision highp int;
#endif

//================
uniform sampler2D sampler0;
uniform vec2 u_texelDelta;
in vec2 r_texcoord;
out vec4 o_color;

//================
float dist(vec2 coord, vec2 source)
{
	vec2 delta = coord - source;
	return sqrt(dot(delta, delta));
}

float color_bloom(vec3 color)
{
	const vec3 gray_coeff = vec3(0.30, 0.59, 0.11);
	float bright = dot(color, gray_coeff);
	return mix(1.0 + shine, 1.0 - shine, bright);
}

vec3 lookup(vec2 pixel_no, float offset_x, float offset_y, vec3 color)
{
	vec2 offset = vec2(offset_x, offset_y);
	float delta = dist(fract(pixel_no), offset + vec2(0.5, 0.5));
	return color * exp(-gamma * delta * color_bloom(color));
}

//================
void main()
{
	float dx = u_texelDelta.x;
	float dy = u_texelDelta.y;

  vec4 v_texcoord1 = vec4(r_texcoord + vec2(-dx, -dy), r_texcoord + vec2(0.0, -dy));
	
	// c20_01
	vec4 v_texcoord2 = vec4(r_texcoord + vec2(dx, -dy), r_texcoord + vec2(-dx, 0.0));
	
	// c21_02
	vec4 v_texcoord3 = vec4(r_texcoord + vec2(dx, 0.0), r_texcoord + vec2(-dx, dy));
	
	// c12_22
	vec4 v_texcoord4 = vec4(r_texcoord + vec2(0.0, dy), r_texcoord + vec2(dx, dy));
	
	// c11
	vec2 v_texcoord5 = r_texcoord;
	
	// pixel_no
	vec2 v_texcoord6 = r_texcoord * (1.0 / u_texelDelta.xy);

	// pixel_no == v_texcoord6
	vec3 mid_color = lookup(v_texcoord6, 0.0, 0.0, texture(sampler0, v_texcoord5).rgb); // c11
	
	vec3 color = vec3(0.0, 0.0, 0.0);
	
	color += lookup(v_texcoord6, -1.0, -1.0, texture(sampler0, v_texcoord1.xy).rgb); // c00_10
	color += lookup(v_texcoord6,  0.0, -1.0, texture(sampler0, v_texcoord1.zw).rgb); // c00_10
	color += lookup(v_texcoord6,  1.0, -1.0, texture(sampler0, v_texcoord2.xy).rgb); // c20_01
	color += lookup(v_texcoord6, -1.0,  0.0, texture(sampler0, v_texcoord2.zw).rgb); // c20_01
	color += mid_color;
	color += lookup(v_texcoord6,  1.0,  0.0, texture(sampler0, v_texcoord3.xy).rgb); // c21_02
	color += lookup(v_texcoord6, -1.0,  1.0, texture(sampler0, v_texcoord3.zw).rgb); // c21_02
	color += lookup(v_texcoord6,  0.0,  1.0, texture(sampler0, v_texcoord4.xy).rgb); // c12_22
	color += lookup(v_texcoord6,  1.0,  1.0, texture(sampler0, v_texcoord4.zw).rgb); // c12_22
	
	vec3 out_color = mix(1.2 * mid_color, color, blend);
	
	o_color = vec4(out_color, 1.0);
}
