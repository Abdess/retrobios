// AA-Color shader, Modified to use in PPSSPP. Grabbed from:
// http://forums.ngemu.com/showthread.php?t=76098

// by guest(r) (guest.r@gmail.com)
// license: GNU-GPL

// Color variables

#ifdef GL_ES
precision mediump float;
precision mediump int;
#endif

const vec3 c_ch = vec3(1.0,1.0,1.0);  //  rgb color channel intensity
const float   a = 1.20 ;              //  saturation 
const float   b = 1.00 ;              //  brightness 
const float   c = 1.25 ;              //  contrast   
const float scaleoffset = 0.8;

// you can use contrast1,contrast2...contrast4 (or contrast0 for speedup)

float contrast0(float x)
{ return x; }

float contrast1(float x)
{ x = x*1.1547-1.0;
  return sign(x)*pow(abs(x),1.0/c)*0.86 +  0.86;}

float contrast2(float x) 
{ return normalize(vec2(pow(x,c),pow(0.86,c))).x*1.72;}

float contrast3(float x)
{ return 1.73*pow(0.57735*x,c); }

float contrast4(float x)
{ return clamp(0.866 + c*(x-0.866),0.05, 1.73); }

uniform sampler2D u_tex;
uniform vec2 u_texelDelta;

in vec2 r_texcoord;
out vec4 o_color;

void main()
{
  float vx = u_texelDelta.x*scaleoffset;
  float vy = u_texelDelta.y*scaleoffset;
  
  vec4 v_texcoord0;
  vec4 v_texcoord1;
  vec4 v_texcoord2;
  vec4 v_texcoord4;
  vec4 v_texcoord5;

  v_texcoord0 = r_texcoord.xyxy;
  v_texcoord1 = v_texcoord0;
  v_texcoord2 = v_texcoord0;
  v_texcoord4 = v_texcoord0;
  v_texcoord5 = v_texcoord0;
  v_texcoord1.y-=vy; 
  v_texcoord2.y+=vy; 
  v_texcoord4.x-=vx; 
  v_texcoord5.x+=vx; 

  vec3 c10 = texture(u_tex, v_texcoord1.xy).xyz; 
  vec3 c01 = texture(u_tex, v_texcoord4.xy).xyz; 
  vec3 c11 = texture(u_tex, v_texcoord0.xy).xyz; 
  vec3 c21 = texture(u_tex, v_texcoord5.xy).xyz; 
  vec3 c12 = texture(u_tex, v_texcoord2.xy).xyz; 

  vec3 dt = vec3(1.0,1.0,1.0);
  float k1=dot(abs(c01-c21),dt);
  float k2=dot(abs(c10-c12),dt);

  vec3 color = (k1*(c10+c12)+k2*(c01+c21)+0.001*c11)/(2.0*(k1+k2)+0.001);

  float x = sqrt(dot(color,color));

  color.r = pow(color.r+0.001,a);
  color.g = pow(color.g+0.001,a);
  color.b = pow(color.b+0.001,a);

  o_color.rgb = contrast4(x)*normalize(color*c_ch)*b;
  o_color.a = 1.0;
}
