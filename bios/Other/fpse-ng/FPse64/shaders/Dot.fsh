precision highp float;
precision highp int;
uniform sampler2D uTex;
uniform highp float resX;
uniform highp float resY;
varying highp vec2 vTexCoord;

varying vec4 v_texcoord1;
varying vec4 v_texcoord2;
varying vec4 v_texcoord3;
varying vec4 v_texcoord4;
varying vec2 v_texcoord5;
varying vec2 v_texcoord6;
float dist(vec2 coord, vec2 source)
{
	vec2 delta = coord - source;
	return sqrt(dot(delta, delta));
}
float color_bloom(vec3 color)
{
	const vec3 gray_coeff = vec3(0.30, 0.59, 0.11);
	float bright = dot(color, gray_coeff);
	return mix(1.0 + 0.05, 1.0 - 0.05, bright);
}
vec3 lookup(vec2 pixel_no, float offset_x, float offset_y, vec3 color)
{
	vec2 offset = vec2(offset_x, offset_y);
	float delta = dist(fract(pixel_no), offset + vec2(0.5, 0.5));
	return color * exp(-2.4 * delta * color_bloom(color));
}
void main()
{
	vec3 mid_color = lookup(v_texcoord6, 0.0, 0.0, texture2D(uTex, v_texcoord5).rgb);	
	vec3 color = vec3(0.0, 0.0, 0.0);
	color += lookup(v_texcoord6, -1.0, -1.0, texture2D(uTex, v_texcoord1.xy).rgb);
	color += lookup(v_texcoord6,  0.0, -1.0, texture2D(uTex, v_texcoord1.zw).rgb);
	color += lookup(v_texcoord6,  1.0, -1.0, texture2D(uTex, v_texcoord2.xy).rgb);
	color += lookup(v_texcoord6, -1.0,  0.0, texture2D(uTex, v_texcoord2.zw).rgb);
	color += mid_color;
	color += lookup(v_texcoord6,  1.0,  0.0, texture2D(uTex, v_texcoord3.xy).rgb);
	color += lookup(v_texcoord6, -1.0,  1.0, texture2D(uTex, v_texcoord3.zw).rgb);
	color += lookup(v_texcoord6,  0.0,  1.0, texture2D(uTex, v_texcoord4.xy).rgb);
	color += lookup(v_texcoord6,  1.0,  1.0, texture2D(uTex, v_texcoord4.zw).rgb);
	vec3 out_color = mix(1.2 * mid_color, color, 0.65);
	gl_FragColor = vec4(out_color, 1.0);
}