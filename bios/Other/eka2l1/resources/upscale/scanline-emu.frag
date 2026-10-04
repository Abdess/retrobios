// Scanline shader
// Author: Themaister
// This code is hereby placed in the public domain.
 
#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif

uniform sampler2D sampler0;
uniform vec2 u_texelDelta;

in vec2 r_texcoord;

out vec4 o_color;

const float base_brightness = 0.95;
const vec2 sine_comp = vec2(0.05, 0.15);

#define pi 3.141592654

void main () {
	vec4 c11 = texture(sampler0, r_texcoord);
  vec2 omega = vec2(pi / u_texelDelta.x, 2.0 * pi / u_texelDelta.x);

	vec4 scanline = c11 * (base_brightness + dot(sine_comp * sin(r_texcoord * omega), vec2(1.0)));
	o_color = clamp(scanline, 0.0, 1.0);
}
