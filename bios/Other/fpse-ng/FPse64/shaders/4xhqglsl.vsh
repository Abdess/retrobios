#ifdef GL_ES
precision mediump float;
precision mediump int;
#endif

attribute vec4 aVertex;
attribute vec2 aTexCoord;

uniform highp float outX;
uniform highp float outY;	

uniform highp float resX;
uniform highp float resY;


varying vec4 v_texcoord0;
varying vec4 v_texcoord1;
varying vec4 v_texcoord2;
varying vec4 v_texcoord3;
varying vec4 v_texcoord4;
varying vec4 v_texcoord5;
varying vec4 v_texcoord6;

void main()
{
  float x = outX*((resX/outX)/2.0);
  float y = outX*((resY/outY)/2.0);
  vec2 dg1 = vec2( x,y);
  vec2 dg2 = vec2(-x,y);
  vec2 sd1 = dg1*0.5;
  vec2 sd2 = dg2*0.5;
  gl_Position = vec4(aVertex.x, aVertex.y, 0.0, 1.0);;
  v_texcoord0=aTexCoord.xyxy;
  v_texcoord1.xy = v_texcoord0.xy - sd1;
  v_texcoord2.xy = v_texcoord0.xy - sd2;
  v_texcoord3.xy = v_texcoord0.xy + sd1;
  v_texcoord4.xy = v_texcoord0.xy + sd2;
  v_texcoord5.xy = v_texcoord0.xy - dg1;
  v_texcoord6.xy = v_texcoord0.xy + dg1;
  v_texcoord5.zw = v_texcoord0.xy - dg2;
  v_texcoord6.zw = v_texcoord0.xy + dg2;
}
