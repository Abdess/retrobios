// Advanced Scanlines (CRT) shader, created to use in PPSSPP.

#ifdef GL_ES
precision mediump float;
precision mediump int;
#endif

uniform sampler2D sampler0;
in vec2 r_texcoord;
out vec4 o_color;

void main()
{
  vec4 u_setting;
  u_setting.xy = vec2(1.0, 0.5);

  float pos0 = ((r_texcoord.y + 1.0) * 170.0*u_setting.x);
  float pos1 = cos((fract( pos0 ) - 0.5)*3.1415926*u_setting.y)*1.5;
  vec4 rgb = texture( sampler0, r_texcoord );
  
  // slight contrast curve
  vec4 color = rgb*0.5+0.5*rgb*rgb*1.2;
  
  // color tint
  color *= vec4(0.9,1.0,0.7, 0.0);
  
  // vignette
  color *= 1.1 - 0.6 * (dot(r_texcoord - 0.5, r_texcoord - 0.5) * 2.0);

  o_color = mix(vec4(0,0,0,0), color, pos1);
}