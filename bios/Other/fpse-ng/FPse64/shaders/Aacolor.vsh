// by guest(r) - guest.r@gmail.com
// license: GNU-GPL

#ifdef GL_ES
precision mediump float;
precision mediump int;
#endif


attribute vec2 aVertex;
attribute vec2 aTexCoord;
uniform highp float outX;
uniform highp float outY;	


varying vec4 v_texcoord0;
varying vec4 v_texcoord1;
varying vec4 v_texcoord2;
varying vec4 v_texcoord3;
varying vec4 v_texcoord4;
varying vec4 v_texcoord5;
varying vec4 v_texcoord6;

float scaleoffset = 0.8;

void main()

{
  float x = (1.0/outX)*scaleoffset;
  float y = (1.0/outY)*scaleoffset;
  gl_Position = vec4(aVertex.x, aVertex.y, 0.0, 1.0);
  v_texcoord0 = aTexCoord.xyxy;
  v_texcoord1 = v_texcoord0;
  v_texcoord2 = v_texcoord0;
  v_texcoord4 = v_texcoord0;
  v_texcoord5 = v_texcoord0;
  v_texcoord1.y-=y; 
  v_texcoord2.y+=y; 
  v_texcoord4.x-=x; 
  v_texcoord5.x+=x; 
}
