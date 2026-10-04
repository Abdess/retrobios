// Natural Vision Shader, modified to use in PPSSPP.

// by ShadX (Modded by SimoneT)
// http://forums.ngemu.com/showthread.php?t=76098

#ifdef GL_ES
precision mediump float;
precision mediump int;
#endif

uniform sampler2D u_tex;
uniform vec2 u_texelDelta;
in vec2 r_texcoord;
out vec4 o_color;

const mat3 RGBtoYIQ = mat3(0.299, 0.596, 0.212, 
                           0.587,-0.275,-0.523, 
                           0.114,-0.321, 0.311);

const mat3 YIQtoRGB = mat3(1.0, 1.0, 1.0,
                           0.95568806036115671171,-0.27158179694405859326,-1.1081773266826619523,
                           0.61985809445637075388,-0.64687381613840131330, 1.7050645599191817149);

const vec3 val00 = vec3( 1.2, 1.2, 1.2);

void main()
{
	vec4 v_texcoord0=r_texcoord.xyxy+vec4(-0.5,-0.5,-1.5,-1.5)*u_texelDelta.xyxy;
	vec4 v_texcoord1=r_texcoord.xyxy+vec4( 0.5,-0.5, 1.5,-1.5)*u_texelDelta.xyxy;
	vec4 v_texcoord2=r_texcoord.xyxy+vec4(-0.5, 0.5,-1.5, 1.5)*u_texelDelta.xyxy;
	vec4 v_texcoord3=r_texcoord.xyxy+vec4( 0.5, 0.5, 1.5, 1.5)*u_texelDelta.xyxy;

	vec3 c0,c1;

	c0 = texture(u_tex,v_texcoord0.xy).xyz;
	c0+=(texture(u_tex,v_texcoord0.zy).xyz)*0.25;
	c0+=(texture(u_tex,v_texcoord0.xw).xyz)*0.25;
	c0+=(texture(u_tex,v_texcoord0.zw).xyz)*0.125;

	c0+= texture(u_tex,v_texcoord1.xy).xyz;
	c0+=(texture(u_tex,v_texcoord1.zy).xyz)*0.25;
	c0+=(texture(u_tex,v_texcoord1.xw).xyz)*0.25;
	c0+=(texture(u_tex,v_texcoord1.zw).xyz)*0.125;

	c0+= texture(u_tex,v_texcoord2.xy).xyz;
	c0+=(texture(u_tex,v_texcoord2.zy).xyz)*0.25;
	c0+=(texture(u_tex,v_texcoord2.xw).xyz)*0.25;
	c0+=(texture(u_tex,v_texcoord2.zw).xyz)*0.125;

	c0+= texture(u_tex,v_texcoord3.xy).xyz;
	c0+=(texture(u_tex,v_texcoord3.zy).xyz)*0.25;
	c0+=(texture(u_tex,v_texcoord3.xw).xyz)*0.25;
	c0+=(texture(u_tex,v_texcoord3.zw).xyz)*0.125;
	c0*=0.153846153846;

	c1=RGBtoYIQ*c0;

	c1=vec3(pow(c1.x,val00.x),c1.yz*val00.yz);

	o_color.rgb=YIQtoRGB*c1;
	o_color.a = 1.0;
}
