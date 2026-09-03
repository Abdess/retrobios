uniform highp float outX;
uniform highp float outY;
attribute highp vec2 aVertex;
attribute highp vec2 aTexCoord;
varying highp vec2 vTexCoord;
varying vec4 v_texcoord1;
varying vec4 v_texcoord2;
varying vec4 v_texcoord3;
varying vec4 v_texcoord4;
varying vec2 v_texcoord5;
varying vec2 v_texcoord6;
void main()
{
	vTexCoord = aTexCoord;
	gl_Position = vec4(aVertex.x, aVertex.y, 0.0, 1.0);
	float dx = 1.0 / 1280.0;
	float dy = 1.0 / 720.0;	
	v_texcoord1 = vec4(vTexCoord + vec2(-dx, -dy), vTexCoord + vec2(0.0, -dy));
	v_texcoord2 = vec4(vTexCoord + vec2(dx, -dy), vTexCoord + vec2(-dx, 0.0));
	v_texcoord3 = vec4(vTexCoord + vec2(dx, 0.0), vTexCoord + vec2(-dx, dy));
	v_texcoord4 = vec4(vTexCoord + vec2(0.0, dy), vTexCoord + vec2(dx, dy));
	v_texcoord5 = vTexCoord;
	v_texcoord6 = vTexCoord * (vec2(1280.0,720.0));
}