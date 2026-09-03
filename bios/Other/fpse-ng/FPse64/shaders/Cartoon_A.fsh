precision mediump float;
uniform sampler2D uTex;
uniform lowp float resX;
uniform lowp float resY;
varying vec2 vTexCoord;
void main()
{
   const float th = 0.10;
   const float bb = 0.50;
   const float pp = 1.50;
	vec2 stp0 = vec2(resX, 0.);
	vec2 st0p = vec2(0., resY);
	vec2 stpp = vec2(resX, resY);
	vec2 stpm = vec2(resX, -resY);	
	vec3 c11 = 	texture2D(uTex, vTexCoord).rgb;
	vec3 c00 =  texture2D(uTex, vTexCoord-stpp).rgb;
	vec3 c22 =  texture2D(uTex, vTexCoord+stpp).rgb;
	vec3 c20 =  texture2D(uTex, vTexCoord-stpm).rgb;
	vec3 c02 =  texture2D(uTex, vTexCoord+stpm).rgb;
	vec3 c01 =  texture2D(uTex, vTexCoord-stp0).rgb;
	vec3 c21 =  texture2D(uTex, vTexCoord+stp0).rgb;
	vec3 c10 =  texture2D(uTex, vTexCoord-st0p).rgb;
	vec3 c12 =  texture2D(uTex, vTexCoord+st0p).rgb;
    vec3 dt = vec3(1.0,1.0,1.0);
	float d1=dot(abs(c00-c22),dt);
	float d2=dot(abs(c20-c02),dt);
	float hl=dot(abs(c01-c21),dt);
	float vl=dot(abs(c10-c12),dt);
	float d = bb*pow(max(d1+d2+hl+vl-th,0.0),pp)/(dot(c11,dt)+0.25);
	gl_FragColor = vec4((1.1-d)*c11, 1.);
}
