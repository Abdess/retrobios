precision mediump float;
varying vec2 vTexCoord;
uniform sampler2D uTex;
uniform float resX;       
uniform float resY;


void main()
{   
	vec4 rgb = texture2D(uTex, vTexCoord.xy);
	
	vec4 intens = smoothstep(0.2,0.8,rgb) + normalize(vec4(rgb.xyz,1.0));
	
	if (fract(gl_FragCoord.y*0.5) > 0.5) intens = rgb * 0.8;
	
	gl_FragColor = intens;
}