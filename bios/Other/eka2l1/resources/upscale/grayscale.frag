// Simple grayscale shader

#ifdef GL_ES
precision mediump float;
precision mediump int;
#endif

uniform sampler2D u_tex;
in vec2 r_texcoord;
out vec4 o_color;

void main() {
  vec3 rgb = texture(u_tex, r_texcoord.xy).xyz;
  float luma = dot(rgb, vec3(0.299, 0.587, 0.114));
  o_color.rgb = vec3(luma, luma, luma);
  o_color.a = 1.0;
}
