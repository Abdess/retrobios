// Simple sharpen shader; created to use in PPSSPP

#ifdef GL_ES
precision mediump float;
precision mediump int;
#endif

uniform sampler2D sampler0;
in vec2 r_texcoord;
out vec4 o_color;

void main()
{
  vec3 color = texture(sampler0, r_texcoord.xy).xyz;
  color -= texture(sampler0, r_texcoord.xy+0.0001).xyz*7.0*0.3;
  color += texture(sampler0, r_texcoord.xy-0.0001).xyz*7.0*0.3;
  o_color.rgb = color;
}
