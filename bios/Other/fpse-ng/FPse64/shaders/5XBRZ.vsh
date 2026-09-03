attribute vec2 aVertex;
attribute vec2 aTexCoord;
uniform highp float outX;
uniform highp float outY;	
varying vec4 v_texture_coordinate;
varying vec4 v_texture_coordinate_1;
varying vec4 v_texture_coordinate_2;
varying vec4 v_texture_coordinate_3;
varying vec4 v_texture_coordinate_4;
varying vec4 v_texture_coordinate_5;
varying vec4 v_texture_coordinate_6;
varying vec4 v_texture_coordinate_7;
void main() {
      float dx = 1.0 / outX;
      float dy = 1.0 / outY;

      //     A1 B1 C1
      //  A0  A  B  C C4
      //  D0  D  E  F F4
      //  G0  G  H  I I4
      //     G5 H5 I5

	  gl_Position = vec4(aVertex.x, aVertex.y, 0.0, 1.0);
      v_texture_coordinate = aTexCoord.xyxy;
      v_texture_coordinate_1 = aTexCoord.xxxy + vec4(-dx, 0.0,  dx, -2.0*dy);  //  A1 B1 C1
      v_texture_coordinate_2 = aTexCoord.xxxy + vec4(-dx, 0.0,  dx,     -dy);  //   A  B  C
      v_texture_coordinate_3 = aTexCoord.xxxy + vec4(-dx, 0.0,  dx,     0.0);  //   D  E  F
      v_texture_coordinate_4 = aTexCoord.xxxy + vec4(-dx, 0.0,  dx,      dy);  //   G  H  I
      v_texture_coordinate_5 = aTexCoord.xxxy + vec4(-dx, 0.0,  dx,  2.0*dy);  //  G5 H5 I5
      v_texture_coordinate_6 = aTexCoord.xyyy + vec4(-2.0*dx,  -dy,  0.0,dy);  //  A0 D0 G0
      v_texture_coordinate_7 = aTexCoord.xyyy + vec4( 2.0*dx,  -dy,  0.0,dy);  //  C4 F4 I4 
    }
