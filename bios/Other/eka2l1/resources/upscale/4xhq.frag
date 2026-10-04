// 4xGLSL HqFilter shader, Modified to use in PPSSPP. Grabbed from:
// http://forums.ngemu.com/showthread.php?t=76098

// by guest(r) (guest.r@gmail.com)
// License: GNU-GPL

// Shader notes: looks better with sprite games

#ifdef GL_ES
precision mediump float;
precision mediump int;
#endif

uniform sampler2D u_tex;
in vec2 r_texcoord;
out vec4 o_color;

uniform vec2 u_pixelDelta;
uniform vec2 u_texelDelta;

const float mx = 0.325;    // start smoothing factor
const float k = -0.250;    // smoothing decrease factor
const float max_w = 0.25;  // max. smoothing weigth
const float min_w =-0.05;  // min smoothing/sharpening weigth

void main()
{

  float x = u_pixelDelta.x*((u_texelDelta.x/u_pixelDelta.x)/2.0);
  float y = u_pixelDelta.y*((u_texelDelta.y/u_pixelDelta.y)/2.0);
  vec2 dg1 = vec2( x,y);
  vec2 dg2 = vec2(-x,y);
  vec2 sd1 = dg1*0.5;
  vec2 sd2 = dg2*0.5;
  
  vec4 v_texcoord0 = r_texcoord.xyxy;
  vec4 v_texcoord1;
  vec4 v_texcoord2;
  vec4 v_texcoord3;
  vec4 v_texcoord4;
  vec4 v_texcoord5;
  vec4 v_texcoord6;

  v_texcoord1.xy = v_texcoord0.xy - sd1;
  v_texcoord2.xy = v_texcoord0.xy - sd2;
  v_texcoord3.xy = v_texcoord0.xy + sd1;
  v_texcoord4.xy = v_texcoord0.xy + sd2;
  v_texcoord5.xy = v_texcoord0.xy - dg1;
  v_texcoord6.xy = v_texcoord0.xy + dg1;
  v_texcoord5.zw = v_texcoord0.xy - dg2;
  v_texcoord6.zw = v_texcoord0.xy + dg2;
 
  vec3 c  = texture(u_tex, v_texcoord0.xy).xyz;
  vec3 i1 = texture(u_tex, v_texcoord1.xy).xyz; 
  vec3 i2 = texture(u_tex, v_texcoord2.xy).xyz; 
  vec3 i3 = texture(u_tex, v_texcoord3.xy).xyz; 
  vec3 i4 = texture(u_tex, v_texcoord4.xy).xyz; 
  vec3 o1 = texture(u_tex, v_texcoord5.xy).xyz; 
  vec3 o3 = texture(u_tex, v_texcoord6.xy).xyz; 
  vec3 o2 = texture(u_tex, v_texcoord5.zw).xyz;
  vec3 o4 = texture(u_tex, v_texcoord6.zw).xyz; 

  vec3 dt = vec3(1.0,1.0,1.0);

  float ko1=dot(abs(o1-c),dt);
  float ko2=dot(abs(o2-c),dt);
  float ko3=dot(abs(o3-c),dt);
  float ko4=dot(abs(o4-c),dt);

  float nsd1 = dot(abs(i1-i3),dt);
  float nsd2 = dot(abs(i2-i4),dt);

  float w1 = step(ko1,ko3)*nsd2;
  float w2 = step(ko2,ko4)*nsd1;
  float w3 = step(ko3,ko1)*nsd2;
  float w4 = step(ko4,ko2)*nsd1;

  c = (w1*o1+w2*o2+w3*o3+w4*o4+0.1*c)/(w1+w2+w3+w4+0.1);

  float lc = c.r+c.g+c.b+0.2;

  w1 = (i1.r+i1.g+i1.b+lc)*0.2; 
  w1 = clamp(k*dot(abs(c-i1),dt)/w1+mx,min_w,max_w);

  w2 = (i2.r+i2.g+i2.b+lc)*0.2; 
  w2 = clamp(k*dot(abs(c-i2),dt)/w2+mx,min_w,max_w);

  w3 = (i3.r+i3.g+i3.b+lc)*0.2;
  w3 = clamp(k*dot(abs(c-i3),dt)/w3+mx,min_w,max_w);

  w4 = (i4.r+i4.g+i4.b+lc)*0.2; 
  w4 = clamp(k*dot(abs(c-i4),dt)/w4+mx,min_w,max_w);

  o_color.rgb = w1*i1 + w2*i2 + w3*i3 + w4*i4 + (1.0-w1-w2-w3-w4)*c;
  o_color.a = 1.0;
}



