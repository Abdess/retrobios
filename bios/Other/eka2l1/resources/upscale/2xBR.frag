/*
   Hyllian's 2xBR Shader
   
   Copyright (C) 2011 Hyllian/Jararaca - sergiogdb@gmail.com
   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/
// filter="nearest" output_width="200%" output_height="200%"

#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif

uniform vec2 u_texelDelta;
uniform sampler2D u_tex;

in vec2 r_texcoord;
out vec4 o_color;

const vec3 dtt = vec3(65536.0, 255.0, 1.0);

float reduce(vec3 color) {
	return dot(color, dtt);
}

void main() {
	vec2 v_texcoord0[3];
	v_texcoord0[0] = r_texcoord;
	v_texcoord0[1] = vec2(0.0, -u_texelDelta.y);
	v_texcoord0[2] = vec2(-u_texelDelta.x, 0.0);

	vec2 fp = fract(v_texcoord0[0] / u_texelDelta);

	vec2 g1 = v_texcoord0[1] * (step(0.5, fp.x) + step(0.5, fp.y) - 1.0) +
			v_texcoord0[2] * (step(0.5, fp.x) - step(0.5, fp.y));
	vec2 g2 = v_texcoord0[1] * (step(0.5, fp.y) - step(0.5, fp.x)) +
			v_texcoord0[2] * (step(0.5, fp.x) + step(0.5, fp.y) - 1.0);

	vec3 B = texture(u_tex, v_texcoord0[0] + g1     ).xyz;
	vec3 C = texture(u_tex, v_texcoord0[0] + g1 - g2).xyz;
	vec3 D = texture(u_tex, v_texcoord0[0]      + g2).xyz;
	vec3 E = texture(u_tex, v_texcoord0[0]          ).xyz;
	vec3 F = texture(u_tex, v_texcoord0[0]      - g2).xyz;
	vec3 G = texture(u_tex, v_texcoord0[0] - g1 + g2).xyz;
	vec3 H = texture(u_tex, v_texcoord0[0] - g1     ).xyz;
	vec3 I = texture(u_tex, v_texcoord0[0] - g1 - g2).xyz;

	float b = reduce(B);
	float c = reduce(C);
	float d = reduce(D);
	float e = reduce(E);
	float f = reduce(F);
	float g = reduce(G);
	float h = reduce(H);
	float i = reduce(I);
	
	o_color.rgb = E;	

	if (h==f && h!=e && ( e==g && (h==i || e==d) || e==c && (h==i || e==b) ))
	{
		o_color.rgb = mix(E, F, 0.5);
	}
}